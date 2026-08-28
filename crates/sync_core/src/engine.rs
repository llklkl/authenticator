use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    BackupStore, ConditionalUpload, MergeReport, Result, SyncAction, SyncError, SyncProvider,
    VaultMerger,
};

pub struct SyncOutcome {
    pub attempts: usize,
    pub uploaded_etag: String,
    pub merged: bool,
    pub action: SyncAction,
    pub report: MergeReport,
    pub encrypted_bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SyncOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyncOutcome")
            .field("attempts", &self.attempts)
            .field("uploaded_etag", &self.uploaded_etag)
            .field("merged", &self.merged)
            .field("action", &self.action)
            .field("report", &self.report)
            .field("encrypted_bytes", &"[REDACTED]")
            .finish()
    }
}

pub struct SyncEngine<P, M, B> {
    provider: P,
    merger: M,
    backups: B,
    max_attempts: usize,
}

impl<P, M, B> SyncEngine<P, M, B>
where
    P: SyncProvider,
    M: VaultMerger,
    B: BackupStore,
{
    pub fn new(provider: P, merger: M, backups: B) -> Self {
        Self {
            provider,
            merger,
            backups,
            max_attempts: 3,
        }
    }

    pub async fn synchronize(&self, local: &[u8], base: Option<&[u8]>) -> Result<SyncOutcome> {
        let mut candidate = Zeroizing::new(local.to_vec());
        let mut merged = false;
        let mut report = MergeReport::default();
        let mut merge_base = base.map(|bytes| Zeroizing::new(bytes.to_vec()));
        for attempt in 1..=self.max_attempts {
            let remote = match self.provider.download().await {
                Ok(remote) => Some(remote),
                Err(SyncError::RemoteNotFound) => None,
                Err(error) => return Err(error),
            };
            let expected_etag = if let Some(remote) = &remote {
                self.backups
                    .store(&remote.encrypted_bytes)
                    .map_err(|_| SyncError::Backup)?;
                if sha256(&candidate) == remote.revision.content_sha256 {
                    return Ok(SyncOutcome {
                        attempts: attempt,
                        uploaded_etag: remote.revision.etag.clone(),
                        merged,
                        action: SyncAction::Unchanged,
                        report,
                        encrypted_bytes: Zeroizing::new(remote.encrypted_bytes.to_vec()),
                    });
                }
                let output = self.merger.merge(
                    merge_base.as_ref().map(|bytes| bytes.as_slice()),
                    &candidate,
                    &remote.encrypted_bytes,
                )?;
                candidate = output.encrypted_bytes;
                report = output.report;
                merged = report.auto_merged_objects > 0 || report.created_conflicts > 0;
                if !output.requires_upload {
                    return Ok(SyncOutcome {
                        attempts: attempt,
                        uploaded_etag: remote.revision.etag.clone(),
                        merged,
                        action: SyncAction::Downloaded,
                        report,
                        encrypted_bytes: candidate,
                    });
                }
                Some(remote.revision.etag.as_str())
            } else {
                None
            };
            let upload = self
                .provider
                .conditional_upload(ConditionalUpload {
                    expected_etag,
                    encrypted_bytes: &candidate,
                })
                .await;
            match upload {
                Ok(revision) => {
                    let verified = self.provider.download().await?;
                    if verified.revision.etag != revision.etag
                        || verified.revision.content_sha256 != sha256(&candidate)
                    {
                        return Err(SyncError::VerificationFailed);
                    }
                    return Ok(SyncOutcome {
                        attempts: attempt,
                        uploaded_etag: revision.etag,
                        merged,
                        action: if remote.is_none() {
                            SyncAction::CreatedRemote
                        } else if merged {
                            SyncAction::Merged
                        } else {
                            SyncAction::Uploaded
                        },
                        report,
                        encrypted_bytes: candidate,
                    });
                }
                Err(SyncError::PreconditionFailed) => {
                    merge_base = remote.map(|object| object.encrypted_bytes);
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(SyncError::RetryLimitReached)
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RemoteObject, RemoteRevision};
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MemoryProvider {
        state: Arc<Mutex<State>>,
    }
    struct State {
        bytes: Vec<u8>,
        version: u64,
        conflict_once: bool,
    }

    impl MemoryProvider {
        fn new(bytes: &[u8], conflict_once: bool) -> Self {
            Self {
                state: Arc::new(Mutex::new(State {
                    bytes: bytes.to_vec(),
                    version: 1,
                    conflict_once,
                })),
            }
        }
    }
    fn revision(state: &State) -> RemoteRevision {
        RemoteRevision {
            etag: format!("v{}", state.version),
            content_sha256: sha256(&state.bytes),
            content_length: state.bytes.len() as u64,
        }
    }
    #[async_trait]
    impl SyncProvider for MemoryProvider {
        async fn download(&self) -> Result<RemoteObject> {
            let state = self.state.lock().unwrap();
            Ok(RemoteObject {
                revision: revision(&state),
                encrypted_bytes: Zeroizing::new(state.bytes.clone()),
            })
        }
        async fn conditional_upload(
            &self,
            request: ConditionalUpload<'_>,
        ) -> Result<RemoteRevision> {
            let mut state = self.state.lock().unwrap();
            if state.conflict_once {
                state.conflict_once = false;
                state.version += 1;
                state.bytes.extend_from_slice(b"+other-device");
                return Err(SyncError::PreconditionFailed);
            }
            if request.expected_etag != Some(revision(&state).etag.as_str()) {
                return Err(SyncError::PreconditionFailed);
            }
            state.bytes = request.encrypted_bytes.to_vec();
            state.version += 1;
            Ok(revision(&state))
        }
    }
    struct ConcatenatingMerger;
    impl VaultMerger for ConcatenatingMerger {
        fn merge(
            &self,
            _base: Option<&[u8]>,
            local: &[u8],
            remote: &[u8],
        ) -> Result<crate::MergeOutput> {
            let mut merged = remote.to_vec();
            merged.extend_from_slice(b"+");
            merged.extend_from_slice(local);
            Ok(crate::MergeOutput {
                encrypted_bytes: Zeroizing::new(merged),
                report: crate::MergeReport {
                    auto_merged_objects: 1,
                    ..crate::MergeReport::default()
                },
                requires_upload: true,
            })
        }
    }
    #[derive(Default)]
    struct MemoryBackups(Mutex<Vec<Vec<u8>>>);
    impl BackupStore for MemoryBackups {
        fn store(&self, snapshot: &[u8]) -> Result<()> {
            self.0.lock().unwrap().push(snapshot.to_vec());
            Ok(())
        }
    }

    #[test]
    fn retries_stale_etag_and_preserves_both_changes() {
        let provider = MemoryProvider::new(b"remote", true);
        let engine = SyncEngine::new(
            provider.clone(),
            ConcatenatingMerger,
            MemoryBackups::default(),
        );
        let outcome = futures_lite::future::block_on(engine.synchronize(b"local", None)).unwrap();
        assert_eq!(outcome.attempts, 2);
        let state = provider.state.lock().unwrap();
        assert!(state.bytes.windows(12).any(|part| part == b"other-device"));
        assert!(state.bytes.windows(5).any(|part| part == b"local"));
        assert_eq!(&*outcome.encrypted_bytes, &state.bytes);
    }

    #[derive(Clone)]
    struct InitiallyMissingProvider {
        state: Arc<Mutex<Option<State>>>,
    }

    #[async_trait]
    impl SyncProvider for InitiallyMissingProvider {
        async fn download(&self) -> Result<RemoteObject> {
            let state = self.state.lock().unwrap();
            let state = state.as_ref().ok_or(SyncError::RemoteNotFound)?;
            Ok(RemoteObject {
                revision: revision(state),
                encrypted_bytes: Zeroizing::new(state.bytes.clone()),
            })
        }

        async fn conditional_upload(
            &self,
            request: ConditionalUpload<'_>,
        ) -> Result<RemoteRevision> {
            let mut state = self.state.lock().unwrap();
            if state.is_some() || request.expected_etag.is_some() {
                return Err(SyncError::PreconditionFailed);
            }
            *state = Some(State {
                bytes: request.encrypted_bytes.to_vec(),
                version: 1,
                conflict_once: false,
            });
            Ok(revision(state.as_ref().unwrap()))
        }
    }

    #[test]
    fn creates_a_missing_remote_without_overwrite_semantics() {
        let provider = InitiallyMissingProvider {
            state: Arc::new(Mutex::new(None)),
        };
        let engine = SyncEngine::new(
            provider.clone(),
            ConcatenatingMerger,
            MemoryBackups::default(),
        );
        let outcome =
            futures_lite::future::block_on(engine.synchronize(b"first vault", None)).unwrap();
        assert_eq!(outcome.attempts, 1);
        assert!(!outcome.merged);
        assert_eq!(&*outcome.encrypted_bytes, b"first vault");
        assert_eq!(
            provider.state.lock().unwrap().as_ref().unwrap().bytes,
            b"first vault"
        );
    }

    #[test]
    fn outcome_debug_redacts_encrypted_bytes() {
        let outcome = SyncOutcome {
            attempts: 1,
            uploaded_etag: "etag".into(),
            merged: false,
            action: SyncAction::Unchanged,
            report: MergeReport::default(),
            encrypted_bytes: Zeroizing::new(b"secret ciphertext marker".to_vec()),
        };
        assert!(!format!("{outcome:?}").contains("secret ciphertext marker"));
    }
}
