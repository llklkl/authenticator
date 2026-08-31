use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    BackupStore, MergeReport, RemoteVfs, Result, SyncAction, SyncError, SyncOutcome, VaultMerger,
    VfsPath, WriteCondition,
};

const COMMIT_VERSION: u32 = 1;
const MAX_COMMITS: usize = 4_096;
const MAX_PARENTS: usize = 64;
const MAX_COMMIT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CommitManifest {
    version: u32,
    blob_sha256: String,
    encrypted_size: u64,
    parents: Vec<String>,
}

pub struct AppendOnlySyncEngine<V, M, B> {
    vfs: V,
    merger: M,
    backups: B,
}

impl<V, M, B> AppendOnlySyncEngine<V, M, B>
where
    V: RemoteVfs,
    M: VaultMerger,
    B: BackupStore,
{
    pub fn new(vfs: V, merger: M, backups: B) -> Self {
        Self {
            vfs,
            merger,
            backups,
        }
    }

    pub async fn synchronize(
        &self,
        local: &[u8],
        local_base: Option<&[u8]>,
        base_commit_id: Option<&str>,
    ) -> Result<SyncOutcome> {
        let mut graph = self.discover_graph(base_commit_id).await?;
        let mut heads = graph.heads();
        if heads.is_empty() {
            let commit_id = self.publish(local, Vec::new()).await?;
            return Ok(outcome(
                commit_id,
                SyncAction::CreatedRemote,
                false,
                MergeReport::default(),
                local,
            ));
        }

        let mut candidate = Zeroizing::new(local.to_vec());
        let mut report = MergeReport::default();
        let mut merged = false;
        let mut requires_upload = heads.len() > 1;
        let mut all_identical = true;
        heads.sort_unstable();
        for head in &heads {
            let remote = self
                .read_blob(
                    graph
                        .manifests
                        .get(head)
                        .ok_or(SyncError::InvalidRemoteHistory)?,
                )
                .await?;
            self.backups.store(&remote).map_err(|_| SyncError::Backup)?;
            if sha256(&candidate) == sha256(&remote) {
                continue;
            }
            all_identical = false;
            let merge_base = if let Some(base_id) = base_commit_id {
                if let Some(common) = graph.lowest_common_ancestor(base_id, head) {
                    Some(
                        self.read_blob(
                            graph
                                .manifests
                                .get(&common)
                                .ok_or(SyncError::InvalidRemoteHistory)?,
                        )
                        .await?,
                    )
                } else {
                    None
                }
            } else {
                local_base.map(|bytes| Zeroizing::new(bytes.to_vec()))
            };
            let output = self.merger.merge(
                merge_base.as_ref().map(|bytes| bytes.as_slice()),
                &candidate,
                &remote,
            )?;
            candidate = output.encrypted_bytes;
            merge_reports(&mut report, &output.report);
            merged |= output.report.auto_merged_objects > 0 || output.report.created_conflicts > 0;
            requires_upload |= output.requires_upload;
        }

        if heads.len() == 1 && all_identical {
            return Ok(outcome(
                heads.remove(0),
                SyncAction::Unchanged,
                false,
                report,
                &candidate,
            ));
        }
        if heads.len() == 1 && !requires_upload {
            return Ok(outcome(
                heads.remove(0),
                SyncAction::Downloaded,
                merged,
                report,
                &candidate,
            ));
        }
        if let Some(base_id) = base_commit_id {
            if valid_id(base_id) && !graph.manifests.contains_key(base_id) {
                graph.load_closure(&self.vfs, [base_id.to_owned()]).await?;
            }
            if valid_id(base_id) {
                heads.push(base_id.to_owned());
            }
        }
        let parents = graph.frontier(heads)?;
        let commit_id = self.publish(&candidate, parents).await?;
        Ok(outcome(
            commit_id,
            if merged || graph.heads().len() > 1 {
                SyncAction::Merged
            } else {
                SyncAction::Uploaded
            },
            merged,
            report,
            &candidate,
        ))
    }

    pub async fn replace_remote(
        &self,
        local: &[u8],
        validate: impl Fn(&[u8]) -> Result<()>,
        base_commit_id: Option<&str>,
    ) -> Result<SyncOutcome> {
        let graph = self.discover_graph(base_commit_id).await?;
        let heads = graph.heads();
        for head in &heads {
            let remote = self
                .read_blob(
                    graph
                        .manifests
                        .get(head)
                        .ok_or(SyncError::InvalidRemoteHistory)?,
                )
                .await?;
            validate(&remote)?;
            self.backups.store(&remote).map_err(|_| SyncError::Backup)?;
        }
        let created = heads.is_empty();
        let parents = graph.frontier(heads)?;
        let commit_id = self.publish(local, parents).await?;
        Ok(outcome(
            commit_id,
            if created {
                SyncAction::CreatedRemote
            } else {
                SyncAction::Uploaded
            },
            false,
            MergeReport::default(),
            local,
        ))
    }

    async fn discover_graph(&self, base_commit_id: Option<&str>) -> Result<CommitGraph> {
        if !self.vfs.capabilities().list || !self.vfs.capabilities().create_only {
            return Err(SyncError::UnsupportedOperation);
        }
        let prefix = VfsPath::new("commits")?;
        let mut continuation = None;
        let mut ids = Vec::new();
        loop {
            let page = self.vfs.list(&prefix, continuation.as_deref()).await?;
            for entry in page.entries {
                if entry.content_length > MAX_COMMIT_BYTES {
                    return Err(SyncError::InvalidRemoteHistory);
                }
                ids.push(commit_id_from_path(&entry.path)?);
                if ids.len() > MAX_COMMITS {
                    return Err(SyncError::InvalidRemoteHistory);
                }
            }
            continuation = page.continuation;
            if continuation.is_none() {
                break;
            }
        }
        if let Some(base_id) = base_commit_id {
            if !valid_id(base_id) {
                return Err(SyncError::InvalidRemoteHistory);
            }
            ids.push(base_id.to_owned());
        }
        let mut graph = CommitGraph::default();
        graph.load_closure(&self.vfs, ids).await?;
        Ok(graph)
    }

    async fn read_blob(&self, manifest: &CommitManifest) -> Result<Zeroizing<Vec<u8>>> {
        let path = VfsPath::new(format!("blobs/{}.kdbx", manifest.blob_sha256))?;
        let object = self.vfs.read(&path).await?;
        if object.revision.content_length != manifest.encrypted_size
            || object.revision.content_sha256 != parse_hash(&manifest.blob_sha256)?
        {
            return Err(SyncError::InvalidRemoteHistory);
        }
        Ok(object.bytes)
    }

    async fn publish(&self, encrypted: &[u8], mut parents: Vec<String>) -> Result<String> {
        parents.sort_unstable();
        parents.dedup();
        if parents.len() > MAX_PARENTS || parents.iter().any(|parent| !valid_id(parent)) {
            return Err(SyncError::InvalidRemoteHistory);
        }
        let blob_sha256 = hex(&sha256(encrypted));
        let blob_path = VfsPath::new(format!("blobs/{blob_sha256}.kdbx"))?;
        self.create_verified(&blob_path, encrypted).await?;
        let manifest = CommitManifest {
            version: COMMIT_VERSION,
            blob_sha256,
            encrypted_size: encrypted.len() as u64,
            parents,
        };
        let bytes = serde_json::to_vec(&manifest).map_err(|_| SyncError::InvalidRemoteHistory)?;
        let commit_id = hex(&sha256(&bytes));
        let commit_path = VfsPath::new(format!("commits/{commit_id}.json"))?;
        self.create_verified(&commit_path, &bytes).await?;
        Ok(commit_id)
    }

    async fn create_verified(&self, path: &VfsPath, bytes: &[u8]) -> Result<()> {
        match self
            .vfs
            .write(path, bytes, WriteCondition::CreateOnly)
            .await
        {
            Ok(_) | Err(SyncError::PreconditionFailed) => {}
            Err(error) => return Err(error),
        }
        let verified = self.vfs.read(path).await?;
        if verified.revision.content_sha256 != sha256(bytes)
            || verified.revision.content_length != bytes.len() as u64
        {
            return Err(SyncError::VerificationFailed);
        }
        Ok(())
    }
}

#[derive(Default)]
struct CommitGraph {
    manifests: HashMap<String, CommitManifest>,
}

impl CommitGraph {
    async fn load_closure<V: RemoteVfs>(
        &mut self,
        vfs: &V,
        ids: impl IntoIterator<Item = String>,
    ) -> Result<()> {
        let mut queue: VecDeque<String> = ids.into_iter().collect();
        while let Some(id) = queue.pop_front() {
            if self.manifests.contains_key(&id) {
                continue;
            }
            if !valid_id(&id) || self.manifests.len() >= MAX_COMMITS {
                return Err(SyncError::InvalidRemoteHistory);
            }
            let path = VfsPath::new(format!("commits/{id}.json"))?;
            let object = vfs.read(&path).await?;
            if object.revision.content_length > MAX_COMMIT_BYTES
                || hex(&sha256(&object.bytes)) != id
            {
                return Err(SyncError::InvalidRemoteHistory);
            }
            let manifest: CommitManifest = serde_json::from_slice(&object.bytes)
                .map_err(|_| SyncError::InvalidRemoteHistory)?;
            let canonical =
                serde_json::to_vec(&manifest).map_err(|_| SyncError::InvalidRemoteHistory)?;
            if canonical.as_slice() != object.bytes.as_slice()
                || manifest.version != COMMIT_VERSION
                || !valid_id(&manifest.blob_sha256)
                || manifest.parents.len() > MAX_PARENTS
                || manifest.parents.iter().any(|parent| !valid_id(parent))
            {
                return Err(SyncError::InvalidRemoteHistory);
            }
            queue.extend(manifest.parents.iter().cloned());
            self.manifests.insert(id, manifest);
        }
        if self.has_cycle() {
            return Err(SyncError::InvalidRemoteHistory);
        }
        Ok(())
    }

    fn heads(&self) -> Vec<String> {
        let referenced: HashSet<&str> = self
            .manifests
            .values()
            .flat_map(|manifest| manifest.parents.iter().map(String::as_str))
            .collect();
        self.manifests
            .keys()
            .filter(|id| !referenced.contains(id.as_str()))
            .cloned()
            .collect()
    }

    fn frontier(&self, ids: Vec<String>) -> Result<Vec<String>> {
        let unique: BTreeSet<String> = ids.into_iter().collect();
        let frontier = unique
            .iter()
            .filter(|candidate| {
                !unique
                    .iter()
                    .any(|other| candidate != &other && self.is_ancestor(candidate, other))
            })
            .cloned()
            .collect::<Vec<_>>();
        if frontier.len() > MAX_PARENTS {
            return Err(SyncError::InvalidRemoteHistory);
        }
        Ok(frontier)
    }

    fn lowest_common_ancestor(&self, first: &str, second: &str) -> Option<String> {
        let first_distances = self.ancestor_distances(first);
        let second_distances = self.ancestor_distances(second);
        first_distances
            .iter()
            .filter_map(|(id, first_distance)| {
                second_distances
                    .get(id)
                    .map(|second_distance| (first_distance + second_distance, id))
            })
            .min_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)))
            .map(|(_, id)| id.clone())
    }

    fn ancestor_distances(&self, start: &str) -> HashMap<String, usize> {
        let mut distances = HashMap::new();
        let mut queue = VecDeque::from([(start.to_owned(), 0usize)]);
        while let Some((id, distance)) = queue.pop_front() {
            if distances
                .get(&id)
                .is_some_and(|existing| *existing <= distance)
            {
                continue;
            }
            distances.insert(id.clone(), distance);
            if let Some(manifest) = self.manifests.get(&id) {
                queue.extend(
                    manifest
                        .parents
                        .iter()
                        .cloned()
                        .map(|parent| (parent, distance + 1)),
                );
            }
        }
        distances
    }

    fn is_ancestor(&self, ancestor: &str, descendant: &str) -> bool {
        self.ancestor_distances(descendant).contains_key(ancestor)
    }

    fn has_cycle(&self) -> bool {
        self.manifests.keys().any(|start| {
            let mut visited = HashSet::new();
            let mut queue = VecDeque::new();
            if let Some(manifest) = self.manifests.get(start) {
                queue.extend(manifest.parents.iter().cloned());
            }
            while let Some(id) = queue.pop_front() {
                if id == *start {
                    return true;
                }
                if visited.insert(id.clone()) {
                    if let Some(manifest) = self.manifests.get(&id) {
                        queue.extend(manifest.parents.iter().cloned());
                    }
                }
            }
            false
        })
    }
}

fn outcome(
    commit_id: String,
    action: SyncAction,
    merged: bool,
    report: MergeReport,
    bytes: &[u8],
) -> SyncOutcome {
    SyncOutcome {
        attempts: 1,
        uploaded_etag: commit_id,
        merged,
        action,
        report,
        encrypted_bytes: Zeroizing::new(bytes.to_vec()),
    }
}

fn merge_reports(target: &mut MergeReport, next: &MergeReport) {
    target.auto_merged_objects = target
        .auto_merged_objects
        .saturating_add(next.auto_merged_objects);
    target.created_conflicts = target
        .created_conflicts
        .saturating_add(next.created_conflicts);
    target.pending_conflicts = next.pending_conflicts;
    target.baseline_rebuilt |= next.baseline_rebuilt;
}

fn commit_id_from_path(path: &VfsPath) -> Result<String> {
    path.as_str()
        .strip_prefix("commits/")
        .and_then(|value| value.strip_suffix(".json"))
        .filter(|value| valid_id(value))
        .map(ToOwned::to_owned)
        .ok_or(SyncError::InvalidRemoteHistory)
}

fn parse_hash(value: &str) -> Result<[u8; 32]> {
    if !valid_id(value) {
        return Err(SyncError::InvalidRemoteHistory);
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| SyncError::InvalidRemoteHistory)?;
    }
    Ok(output)
}

fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::*;
    use crate::{MergeOutput, VfsCapabilities, VfsListEntry, VfsListPage, VfsObject, VfsRevision};

    #[derive(Clone, Default)]
    struct MemoryVfs {
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        hidden: Arc<Mutex<HashSet<String>>>,
        conditions: Arc<Mutex<Vec<&'static str>>>,
    }

    impl MemoryVfs {
        fn hide(&self, path: String) {
            self.hidden.lock().unwrap().insert(path);
        }

        fn show_all(&self) {
            self.hidden.lock().unwrap().clear();
        }
    }

    #[async_trait]
    impl RemoteVfs for MemoryVfs {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities {
                list: true,
                create_only: true,
                match_revision: false,
            }
        }

        async fn read(&self, path: &VfsPath) -> Result<VfsObject> {
            let bytes = self
                .objects
                .lock()
                .unwrap()
                .get(path.as_str())
                .cloned()
                .ok_or(SyncError::RemoteNotFound)?;
            Ok(VfsObject {
                revision: VfsRevision::new(
                    hex(&sha256(&bytes)),
                    sha256(&bytes),
                    bytes.len() as u64,
                )?,
                bytes: Zeroizing::new(bytes),
            })
        }

        async fn list(&self, prefix: &VfsPath, _continuation: Option<&str>) -> Result<VfsListPage> {
            let prefix = format!("{}/", prefix.as_str());
            let hidden = self.hidden.lock().unwrap();
            let entries = self
                .objects
                .lock()
                .unwrap()
                .iter()
                .filter(|(path, _)| path.starts_with(&prefix) && !hidden.contains(*path))
                .map(|(path, bytes)| VfsListEntry {
                    path: VfsPath::new(path.clone()).unwrap(),
                    content_length: bytes.len() as u64,
                })
                .collect();
            Ok(VfsListPage {
                entries,
                continuation: None,
            })
        }

        async fn write(
            &self,
            path: &VfsPath,
            bytes: &[u8],
            condition: WriteCondition<'_>,
        ) -> Result<VfsRevision> {
            self.conditions.lock().unwrap().push(match condition {
                WriteCondition::CreateOnly => "create_only",
                WriteCondition::Match(_) => "match",
            });
            if !matches!(condition, WriteCondition::CreateOnly) {
                return Err(SyncError::ConditionalWritesUnsupported);
            }
            let mut objects = self.objects.lock().unwrap();
            if objects.contains_key(path.as_str()) {
                return Err(SyncError::PreconditionFailed);
            }
            objects.insert(path.as_str().to_owned(), bytes.to_vec());
            VfsRevision::new(hex(&sha256(bytes)), sha256(bytes), bytes.len() as u64)
        }
    }

    struct SetMerger;

    impl VaultMerger for SetMerger {
        fn merge(&self, _base: Option<&[u8]>, local: &[u8], remote: &[u8]) -> Result<MergeOutput> {
            let mut values = BTreeSet::new();
            for source in [local, remote] {
                values.extend(
                    std::str::from_utf8(source)
                        .map_err(|_| SyncError::Merge)?
                        .split(',')
                        .filter(|value| !value.is_empty()),
                );
            }
            let merged = values
                .into_iter()
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes();
            Ok(MergeOutput {
                requires_upload: merged != remote,
                encrypted_bytes: Zeroizing::new(merged),
                report: MergeReport {
                    auto_merged_objects: 1,
                    ..MergeReport::default()
                },
            })
        }
    }

    #[derive(Default)]
    struct MemoryBackups(Mutex<Vec<Vec<u8>>>);

    impl BackupStore for MemoryBackups {
        fn store(&self, encrypted_snapshot: &[u8]) -> Result<()> {
            self.0.lock().unwrap().push(encrypted_snapshot.to_vec());
            Ok(())
        }
    }

    #[test]
    fn concurrent_hidden_branch_is_merged_without_overwrite() {
        let vfs = MemoryVfs::default();
        let first = futures_lite::future::block_on(
            AppendOnlySyncEngine::new(vfs.clone(), SetMerger, MemoryBackups::default())
                .synchronize(b"base", None, None),
        )
        .unwrap();
        let branch_b = futures_lite::future::block_on(
            AppendOnlySyncEngine::new(vfs.clone(), SetMerger, MemoryBackups::default())
                .synchronize(b"base,b", Some(b"base"), Some(&first.uploaded_etag)),
        )
        .unwrap();
        vfs.hide(format!("commits/{}.json", branch_b.uploaded_etag));
        let branch_c = futures_lite::future::block_on(
            AppendOnlySyncEngine::new(vfs.clone(), SetMerger, MemoryBackups::default())
                .synchronize(b"base,c", Some(b"base"), Some(&first.uploaded_etag)),
        )
        .unwrap();
        vfs.show_all();
        let merged = futures_lite::future::block_on(
            AppendOnlySyncEngine::new(vfs.clone(), SetMerger, MemoryBackups::default())
                .synchronize(
                    &branch_c.encrypted_bytes,
                    Some(&branch_c.encrypted_bytes),
                    Some(&branch_c.uploaded_etag),
                ),
        )
        .unwrap();
        assert_eq!(&*merged.encrypted_bytes, b"b,base,c");
        assert_eq!(merged.action, SyncAction::Merged);
        assert!(
            vfs.conditions
                .lock()
                .unwrap()
                .iter()
                .all(|value| *value == "create_only")
        );
        let graph = futures_lite::future::block_on(
            AppendOnlySyncEngine::new(vfs, SetMerger, MemoryBackups::default())
                .discover_graph(Some(&merged.uploaded_etag)),
        )
        .unwrap();
        assert_eq!(graph.heads(), vec![merged.uploaded_etag]);
    }

    #[test]
    fn tampered_commit_fails_closed_before_merge_or_write() {
        let vfs = MemoryVfs::default();
        let first = futures_lite::future::block_on(
            AppendOnlySyncEngine::new(vfs.clone(), SetMerger, MemoryBackups::default())
                .synchronize(b"base", None, None),
        )
        .unwrap();
        let commit_path = format!("commits/{}.json", first.uploaded_etag);
        vfs.objects
            .lock()
            .unwrap()
            .insert(commit_path, b"{\"tampered\":true}".to_vec());
        let writes_before = vfs.conditions.lock().unwrap().len();
        let result = futures_lite::future::block_on(
            AppendOnlySyncEngine::new(vfs.clone(), SetMerger, MemoryBackups::default())
                .synchronize(b"local", None, None),
        );
        assert!(matches!(result, Err(SyncError::InvalidRemoteHistory)));
        assert_eq!(vfs.conditions.lock().unwrap().len(), writes_before);
    }
}
