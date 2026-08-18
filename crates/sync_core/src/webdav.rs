use std::{fmt, time::Duration};

use async_trait::async_trait;
use reqwest::{Client, StatusCode, header};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use crate::{ConditionalUpload, RemoteObject, RemoteRevision, Result, SyncError, SyncProvider};

/// WebDAV provider restricted to ETag-based optimistic concurrency.
pub struct WebDavProvider {
    client: Client,
    endpoint: Url,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl WebDavProvider {
    pub fn new(
        endpoint: &str,
        username: String,
        password: String,
        allow_insecure_http: bool,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint).map_err(|_| SyncError::InvalidConfiguration)?;
        if endpoint.username() != "" || endpoint.password().is_some() {
            return Err(SyncError::InvalidConfiguration);
        }
        match endpoint.scheme() {
            "https" => {}
            "http" if allow_insecure_http => {}
            _ => return Err(SyncError::InvalidConfiguration),
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|_| SyncError::Provider)?;
        Ok(Self {
            client,
            endpoint,
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
        })
    }

    fn request(&self, method: reqwest::Method) -> reqwest::RequestBuilder {
        self.client
            .request(method, self.endpoint.clone())
            .basic_auth(&*self.username, Some(&*self.password))
    }

    async fn head_etag(&self) -> Result<String> {
        let response = self
            .request(reqwest::Method::HEAD)
            .send()
            .await
            .map_err(|_| SyncError::Provider)?;
        if !response.status().is_success() {
            return Err(SyncError::Provider);
        }
        strong_etag(response.headers())
    }
}

impl fmt::Debug for WebDavProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebDavProvider")
            .field("endpoint", &"[REDACTED]")
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
impl SyncProvider for WebDavProvider {
    async fn download(&self) -> Result<RemoteObject> {
        let response = self
            .request(reqwest::Method::GET)
            .send()
            .await
            .map_err(|_| SyncError::Provider)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(SyncError::RemoteNotFound);
        }
        if !response.status().is_success() {
            return Err(SyncError::Provider);
        }
        let etag = strong_etag(response.headers())?;
        let bytes = response.bytes().await.map_err(|_| SyncError::Provider)?;
        let revision = RemoteRevision {
            etag,
            content_sha256: Sha256::digest(&bytes).into(),
            content_length: bytes.len() as u64,
        };
        Ok(RemoteObject {
            revision,
            encrypted_bytes: Zeroizing::new(bytes.to_vec()),
        })
    }

    async fn conditional_upload(&self, request: ConditionalUpload<'_>) -> Result<RemoteRevision> {
        let content_hash: [u8; 32] = Sha256::digest(request.encrypted_bytes).into();
        let content_length = request.encrypted_bytes.len() as u64;
        let mut upload = self
            .request(reqwest::Method::PUT)
            .header(header::CONTENT_TYPE, "application/octet-stream");
        upload = if let Some(etag) = request.expected_etag {
            upload.header(header::IF_MATCH, etag)
        } else {
            upload.header(header::IF_NONE_MATCH, "*")
        };
        let response = upload
            .body(request.encrypted_bytes.to_vec())
            .send()
            .await
            .map_err(|_| SyncError::Provider)?;
        if response.status() == StatusCode::PRECONDITION_FAILED {
            return Err(SyncError::PreconditionFailed);
        }
        if !response.status().is_success() {
            return Err(SyncError::Provider);
        }
        let etag = match strong_etag(response.headers()) {
            Ok(etag) => etag,
            Err(SyncError::ConditionalWritesUnsupported) => self.head_etag().await?,
            Err(error) => return Err(error),
        };
        Ok(RemoteRevision {
            etag,
            content_sha256: content_hash,
            content_length,
        })
    }
}

fn strong_etag(headers: &header::HeaderMap) -> Result<String> {
    headers
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.starts_with("W/"))
        .map(ToOwned::to_owned)
        .ok_or(SyncError::ConditionalWritesUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        thread,
    };

    #[test]
    fn rejects_credentials_in_url_and_plain_http_by_default() {
        assert!(matches!(
            WebDavProvider::new(
                "https://user:password@example.com/vault.kdbx",
                String::new(),
                String::new(),
                false,
            ),
            Err(SyncError::InvalidConfiguration)
        ));
        assert!(matches!(
            WebDavProvider::new(
                "http://example.com/vault.kdbx",
                String::new(),
                String::new(),
                false,
            ),
            Err(SyncError::InvalidConfiguration)
        ));
    }

    #[test]
    fn debug_never_contains_endpoint_or_credentials() {
        let provider = WebDavProvider::new(
            "https://example.com/private/vault.kdbx",
            "alice".into(),
            "private-password".into(),
            false,
        )
        .unwrap();
        let debug = format!("{provider:?}");
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("private-password"));
    }

    #[test]
    fn accepts_only_strong_etags() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ETAG, header::HeaderValue::from_static("W/\"weak\""));
        assert_eq!(
            strong_etag(&headers),
            Err(SyncError::ConditionalWritesUnsupported)
        );
        headers.insert(header::ETAG, header::HeaderValue::from_static("\"strong\""));
        assert_eq!(strong_etag(&headers).unwrap(), "\"strong\"");
    }

    #[test]
    fn remote_creation_uses_if_none_match_star() {
        let (endpoint, requests) = serve_responses(vec![
            "HTTP/1.1 201 Created\r\nETag: \"v1\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let provider = WebDavProvider::new(&endpoint, String::new(), String::new(), true).unwrap();
        let runtime = runtime();
        let revision = runtime
            .block_on(provider.conditional_upload(ConditionalUpload {
                expected_etag: None,
                encrypted_bytes: b"encrypted vault",
            }))
            .unwrap();
        assert_eq!(revision.etag, "\"v1\"");
        let request = requests.recv().unwrap().to_ascii_lowercase();
        assert!(request.starts_with("put /vault.kdbx"));
        assert!(request.contains("if-none-match: *"));
        assert!(!request.contains("if-match:"));
    }

    #[test]
    fn falls_back_to_head_when_put_omits_etag() {
        let (endpoint, requests) = serve_responses(vec![
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nETag: \"from-head\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let provider = WebDavProvider::new(&endpoint, String::new(), String::new(), true).unwrap();
        let revision = runtime()
            .block_on(provider.conditional_upload(ConditionalUpload {
                expected_etag: Some("\"old\""),
                encrypted_bytes: b"encrypted vault",
            }))
            .unwrap();
        assert_eq!(revision.etag, "\"from-head\"");
        let put = requests.recv().unwrap().to_ascii_lowercase();
        let head = requests.recv().unwrap().to_ascii_lowercase();
        assert!(put.contains("if-match: \"old\""));
        assert!(head.starts_with("head /vault.kdbx"));
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn serve_responses(responses: Vec<&'static str>) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_headers(&mut stream);
                sender.send(request).unwrap();
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });
        (format!("http://{address}/vault.kdbx"), receiver)
    }

    fn read_headers(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        String::from_utf8(bytes).unwrap()
    }
}
