use std::{
    collections::BTreeMap,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest as Md5Digest, Md5};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use quick_xml::de::from_str;
use reqwest::{Client, Method, StatusCode, header};
use serde::Deserialize;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    RemoteVfs, Result, SyncError, VfsCapabilities, VfsListEntry, VfsListPage, VfsObject, VfsPath,
    VfsRevision, WriteCondition,
};

const SIGNATURE_TTL_SECONDS: u64 = 900;
const MAX_REMOTE_OBJECT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LIST_KEYS: &str = "1000";
const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'=')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b']');
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = QUERY_ENCODE_SET;

type HmacSha1 = Hmac<Sha1>;

pub struct TencentCosVfs {
    client: Client,
    host: String,
    prefix: VfsPath,
    secret_id: Zeroizing<String>,
    secret_key: Zeroizing<String>,
}

impl TencentCosVfs {
    pub fn new(
        bucket: &str,
        region: &str,
        prefix: &str,
        secret_id: String,
        secret_key: String,
    ) -> Result<Self> {
        if !valid_bucket(bucket)
            || !valid_region(region)
            || secret_id.trim().is_empty()
            || secret_key.is_empty()
        {
            return Err(SyncError::InvalidConfiguration);
        }
        let prefix = VfsPath::new(prefix.trim_matches('/'))?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|_| SyncError::Provider)?;
        Ok(Self {
            client,
            host: format!("{bucket}.cos.{region}.myqcloud.com"),
            prefix,
            secret_id: Zeroizing::new(secret_id),
            secret_key: Zeroizing::new(secret_key),
        })
    }

    pub fn location_fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"tencent-cos-v1\0");
        digest.update(self.host.as_bytes());
        digest.update(b"\0");
        digest.update(self.prefix.as_str().as_bytes());
        digest.finalize().into()
    }

    pub async fn ensure_versioning_disabled(&self) -> Result<()> {
        let query = BTreeMap::from([("versioning".to_owned(), String::new())]);
        let response = self
            .send(Method::GET, "", &query, BTreeMap::new(), None)
            .await?;
        if !response.status().is_success() {
            return Err(SyncError::Provider);
        }
        let body = response.text().await.map_err(|_| SyncError::Provider)?;
        let configuration: VersioningConfiguration =
            from_str(&body).map_err(|_| SyncError::Provider)?;
        if configuration
            .status
            .as_deref()
            .is_some_and(|status| !status.is_empty())
        {
            return Err(SyncError::UnsafeBucketVersioning);
        }
        Ok(())
    }

    fn object_key(&self, path: &VfsPath) -> String {
        if path == &VfsPath::root() {
            self.prefix.as_str().to_owned()
        } else {
            format!("{}/{}", self.prefix.as_str(), path.as_str())
        }
    }

    async fn send(
        &self,
        method: Method,
        object_key: &str,
        query: &BTreeMap<String, String>,
        mut signed_headers: BTreeMap<String, String>,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response> {
        signed_headers.insert("host".to_owned(), self.host.clone());
        let uri_path = encode_path(object_key);
        let authorization = authorization(
            &method,
            &uri_path,
            query,
            &signed_headers,
            &self.secret_id,
            &self.secret_key,
            unix_seconds()?,
        )?;
        let mut url = format!("https://{}{}", self.host, uri_path);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&canonical_query(query));
        }
        let mut request = self
            .client
            .request(method, url)
            .header(header::AUTHORIZATION, authorization);
        for (name, value) in signed_headers {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        request.send().await.map_err(|_| SyncError::Provider)
    }
}

impl fmt::Debug for TencentCosVfs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TencentCosVfs")
            .field("location", &"[REDACTED]")
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
impl RemoteVfs for TencentCosVfs {
    fn capabilities(&self) -> VfsCapabilities {
        VfsCapabilities {
            list: true,
            create_only: true,
            match_revision: false,
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<VfsObject> {
        let response = self
            .send(
                Method::GET,
                &self.object_key(path),
                &BTreeMap::new(),
                BTreeMap::new(),
                None,
            )
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(SyncError::RemoteNotFound);
        }
        if !response.status().is_success() {
            return Err(SyncError::Provider);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_REMOTE_OBJECT_BYTES)
        {
            return Err(SyncError::InvalidRemoteHistory);
        }
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .ok_or(SyncError::Provider)?
            .to_owned();
        let bytes = response.bytes().await.map_err(|_| SyncError::Provider)?;
        if bytes.len() as u64 > MAX_REMOTE_OBJECT_BYTES {
            return Err(SyncError::InvalidRemoteHistory);
        }
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        Ok(VfsObject {
            revision: VfsRevision::new(etag, hash, bytes.len() as u64)?,
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }

    async fn list(&self, prefix: &VfsPath, continuation: Option<&str>) -> Result<VfsListPage> {
        let requested_prefix = format!("{}/", self.object_key(prefix));
        let mut query = BTreeMap::from([
            ("max-keys".to_owned(), MAX_LIST_KEYS.to_owned()),
            ("prefix".to_owned(), requested_prefix.clone()),
        ]);
        if let Some(marker) = continuation {
            if marker.chars().any(char::is_control) {
                return Err(SyncError::InvalidRemoteHistory);
            }
            query.insert("marker".to_owned(), marker.to_owned());
        }
        let response = self
            .send(Method::GET, "", &query, BTreeMap::new(), None)
            .await?;
        if !response.status().is_success() {
            return Err(SyncError::Provider);
        }
        let body = response.text().await.map_err(|_| SyncError::Provider)?;
        let result: ListBucketResult = from_str(&body).map_err(|_| SyncError::Provider)?;
        let base = format!("{}/", self.prefix.as_str());
        let mut entries = Vec::with_capacity(result.contents.len());
        for item in result.contents {
            let relative = item
                .key
                .strip_prefix(&base)
                .ok_or(SyncError::InvalidRemoteHistory)?;
            entries.push(VfsListEntry {
                path: VfsPath::new(relative)?,
                content_length: item.size,
            });
        }
        let continuation = if result.is_truncated {
            result
                .next_marker
                .or_else(|| entries.last().map(|entry| self.object_key(&entry.path)))
        } else {
            None
        };
        if result.is_truncated && continuation.is_none() {
            return Err(SyncError::InvalidRemoteHistory);
        }
        Ok(VfsListPage {
            entries,
            continuation,
        })
    }

    async fn write(
        &self,
        path: &VfsPath,
        bytes: &[u8],
        condition: WriteCondition<'_>,
    ) -> Result<VfsRevision> {
        if !matches!(condition, WriteCondition::CreateOnly) {
            return Err(SyncError::ConditionalWritesUnsupported);
        }
        if bytes.len() as u64 > MAX_REMOTE_OBJECT_BYTES {
            return Err(SyncError::InvalidConfiguration);
        }
        let content_md5 = BASE64.encode(Md5::digest(bytes));
        let headers = BTreeMap::from([
            ("content-length".to_owned(), bytes.len().to_string()),
            ("content-md5".to_owned(), content_md5),
            (
                "content-type".to_owned(),
                "application/octet-stream".to_owned(),
            ),
            ("x-cos-forbid-overwrite".to_owned(), "true".to_owned()),
        ]);
        let response = self
            .send(
                Method::PUT,
                &self.object_key(path),
                &BTreeMap::new(),
                headers,
                Some(bytes.to_vec()),
            )
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Err(SyncError::PreconditionFailed);
        }
        if !response.status().is_success() {
            return Err(SyncError::Provider);
        }
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .ok_or(SyncError::Provider)?
            .to_owned();
        VfsRevision::new(etag, Sha256::digest(bytes).into(), bytes.len() as u64)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VersioningConfiguration {
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListBucketResult {
    #[serde(default)]
    contents: Vec<ListObject>,
    #[serde(default)]
    is_truncated: bool,
    next_marker: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListObject {
    key: String,
    size: u64,
}

fn authorization(
    method: &Method,
    uri_path: &str,
    query: &BTreeMap<String, String>,
    headers: &BTreeMap<String, String>,
    secret_id: &str,
    secret_key: &str,
    now: u64,
) -> Result<String> {
    let key_time = format!("{now};{}", now.saturating_add(SIGNATURE_TTL_SECONDS));
    let query_string = canonical_query(query);
    let header_string = canonical_headers(headers);
    let http_string = format!(
        "{}\n{}\n{}\n{}\n",
        method.as_str().to_ascii_lowercase(),
        uri_path,
        query_string,
        header_string
    );
    let string_to_sign = format!("sha1\n{key_time}\n{}\n", hex(&Sha1::digest(http_string)));
    let sign_key = hmac_sha1(secret_key.as_bytes(), key_time.as_bytes())?;
    let signature = hex(&hmac_sha1(
        hex(&sign_key).as_bytes(),
        string_to_sign.as_bytes(),
    )?);
    Ok(format!(
        "q-sign-algorithm=sha1&q-ak={}&q-sign-time={key_time}&q-key-time={key_time}&q-header-list={}&q-url-param-list={}&q-signature={signature}",
        encode(secret_id),
        headers.keys().cloned().collect::<Vec<_>>().join(";"),
        query.keys().cloned().collect::<Vec<_>>().join(";")
    ))
}

fn canonical_query(values: &BTreeMap<String, String>) -> String {
    values
        .iter()
        .map(|(key, value)| format!("{}={}", encode(&key.to_ascii_lowercase()), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_headers(values: &BTreeMap<String, String>) -> String {
    values
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                encode(&key.to_ascii_lowercase()),
                encode(value.trim())
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn hmac_sha1(key: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut mac = HmacSha1::new_from_slice(key).map_err(|_| SyncError::Provider)?;
    mac.update(value);
    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

fn encode(value: &str) -> String {
    utf8_percent_encode(value, QUERY_ENCODE_SET).to_string()
}

fn encode_path(object_key: &str) -> String {
    if object_key.is_empty() {
        return "/".to_owned();
    }
    format!(
        "/{}",
        object_key
            .split('/')
            .map(|segment| utf8_percent_encode(segment, PATH_SEGMENT_ENCODE_SET).to_string())
            .collect::<Vec<_>>()
            .join("/")
    )
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

fn unix_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| SyncError::Provider)
}

fn valid_bucket(value: &str) -> bool {
    let valid_chars = value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    valid_chars
        && (3..=63).contains(&value.len())
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value.rsplit_once('-').is_some_and(|(_, app_id)| {
            (5..=20).contains(&app_id.len()) && app_id.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn valid_region(value: &str) -> bool {
    (3..=32).contains(&value.len())
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_location_and_redacts_configuration() {
        assert!(
            TencentCosVfs::new(
                "vault-1250000000",
                "ap-guangzhou",
                "authenticator/personal",
                "AKID-private".into(),
                "secret-key".into(),
            )
            .is_ok()
        );
        assert!(
            TencentCosVfs::new(
                "vault.example.com",
                "ap-guangzhou",
                "prefix",
                "id".into(),
                "key".into(),
            )
            .is_err()
        );
        let value = TencentCosVfs::new(
            "vault-1250000000",
            "ap-guangzhou",
            "private/prefix",
            "private-id".into(),
            "private-key".into(),
        )
        .unwrap();
        let debug = format!("{value:?}");
        assert!(!debug.contains("private"));
        assert!(!debug.contains("vault-1250000000"));
    }

    #[test]
    fn signing_is_deterministic_and_signs_host() {
        let headers = BTreeMap::from([(
            "host".to_owned(),
            "examplebucket-1250000000.cos.ap-beijing.myqcloud.com".to_owned(),
        )]);
        let first = authorization(
            &Method::GET,
            "/exampleobject",
            &BTreeMap::new(),
            &headers,
            "AKIDEXAMPLE",
            "secret",
            1_600_000_000,
        )
        .unwrap();
        let second = authorization(
            &Method::GET,
            "/exampleobject",
            &BTreeMap::new(),
            &headers,
            "AKIDEXAMPLE",
            "secret",
            1_600_000_000,
        )
        .unwrap();
        assert_eq!(first, second);
        assert!(first.contains("q-header-list=host"));
        assert!(!first.contains("secret"));
    }

    #[test]
    fn parses_list_and_versioning_xml_without_response_leakage() {
        let list: ListBucketResult = from_str(
            "<ListBucketResult><IsTruncated>true</IsTruncated><NextMarker>x</NextMarker><Contents><Key>prefix/commits/a.json</Key><Size>42</Size></Contents></ListBucketResult>",
        )
        .unwrap();
        assert!(list.is_truncated);
        assert_eq!(list.contents[0].size, 42);
        let disabled: VersioningConfiguration =
            from_str("<VersioningConfiguration></VersioningConfiguration>").unwrap();
        assert!(disabled.status.is_none());
    }
}
