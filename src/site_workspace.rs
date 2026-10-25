use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::controlled_crawler;
use crate::public_policy::PublicCrawlPolicy;
use crate::storage::PersistentIndex;

const MANIFEST_FILE: &str = "workspace.json";
const MANIFEST_MAX_BYTES: usize = 16 * 1024;
const WORKSPACE_SCHEMA: &str = "ley-site-workspace-v1";
const MAX_PUBLIC_REQUESTS_PER_RUN: usize = 12;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkspaceManifest {
    schema: String,
    policy_path: PathBuf,
    policy_sha256: String,
    source_id: String,
    store_identity: String,
    created_at_ms: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct SiteWorkspace {
    store: PathBuf,
    frontier: PathBuf,
    manifest: WorkspaceManifest,
}

pub(crate) struct SiteCommandOutput {
    pub json: String,
    pub success: bool,
}

impl SiteWorkspace {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let root = existing_private_directory(path.as_ref(), "workspace")?;
        let manifest_path = root.join(MANIFEST_FILE);
        let bytes = read_private_file(&manifest_path, MANIFEST_MAX_BYTES)?;
        let manifest: WorkspaceManifest = serde_json::from_slice(&bytes)
            .map_err(|_| "workspace manifest is malformed".to_owned())?;
        validate_manifest(&manifest)?;

        let store = root.join("store");
        let frontier = root.join("frontier.sqlite");
        require_owned_directory(&store, "workspace store")?;
        require_owned_regular_file(&frontier, "workspace frontier")?;
        let index = PersistentIndex::open(&store)
            .map_err(|_| "workspace store is unavailable or invalid".to_owned())?;
        if hex(&index.store_identity()) != manifest.store_identity {
            return Err("workspace store identity does not match its manifest".to_owned());
        }
        let binding = index
            .public_collection_binding()
            .map_err(|_| "workspace public collection admission is unavailable".to_owned())?;
        if !binding.as_ref().is_some_and(|(digest, source_id)| {
            digest == &manifest.policy_sha256 && source_id == &manifest.source_id
        }) {
            return Err(
                "workspace policy binding does not match the protected store admission".to_owned(),
            );
        }
        Ok(Self {
            store,
            frontier,
            manifest,
        })
    }

    pub(crate) fn store_path(&self) -> &Path {
        &self.store
    }

    fn load_bound_policy(&self) -> Result<PublicCrawlPolicy, String> {
        let policy = PublicCrawlPolicy::load_approved(
            &self.manifest.policy_path,
            &self.manifest.policy_sha256,
        )
        .map_err(|error| format!("workspace policy binding is unavailable: {error}"))?;
        let summary = policy
            .site_source_summary()
            .map_err(|_| "workspace policy must identify exactly one source".to_owned())?;
        if summary.id != self.manifest.source_id {
            return Err("workspace source identity does not match its pinned policy".to_owned());
        }
        Ok(policy)
    }

    pub(crate) fn status_json(&self) -> Result<String, String> {
        let policy = self.load_bound_policy()?;
        let summary = policy
            .site_source_summary()
            .map_err(|_| "workspace policy must identify exactly one source".to_owned())?;
        let crawl: Value = serde_json::from_str(
            &crate::crawl_status_json(
                &self.store,
                &self.frontier,
                Some(&self.manifest.source_id),
                None,
                false,
            )
            .map_err(|_| "workspace crawl status is unavailable".to_owned())?,
        )
        .map_err(|_| "workspace crawl status is malformed".to_owned())?;
        serde_json::to_string_pretty(&json!({
            "schema": "ley-site-status-v1",
            "backend": "controlled_crawler",
            "readOnly": true,
            "policySha256": self.manifest.policy_sha256,
            "workspaceCreatedAtMs": self.manifest.created_at_ms,
            "source": summary,
            "crawl": crawl,
        }))
        .map_err(|_| "could not serialize workspace status".to_owned())
    }

    pub(crate) fn http_status_json(&self) -> Result<Value, String> {
        let policy = self.load_bound_policy()?;
        let summary = policy
            .site_source_summary()
            .map_err(|_| "workspace policy must identify exactly one source".to_owned())?;
        let crawl: Value = serde_json::from_str(
            &crate::crawl_status_json(
                &self.store,
                &self.frontier,
                Some(&self.manifest.source_id),
                None,
                false,
            )
            .map_err(|_| "workspace crawl status is unavailable".to_owned())?,
        )
        .map_err(|_| "workspace crawl status is malformed".to_owned())?;
        let source = crawl
            .get("sources")
            .and_then(Value::as_array)
            .and_then(|sources| sources.first())
            .ok_or_else(|| "workspace source status is unavailable".to_owned())?;
        let requests = source
            .get("persistentRequests")
            .cloned()
            .unwrap_or(Value::Null);
        let permissions = json!({
            "fetchRecorded": summary.permissions.fetch_granted(),
            "storageRecorded": summary.permissions.storage_granted(),
            "indexRecorded": summary.permissions.index_granted(),
            "displayRecorded": summary.permissions.display_granted(),
        });
        Ok(json!({
            "schema": "ley-site-http-status-v1",
            "backend": "controlled_crawler",
            "readOnly": true,
            "source": {
                "id": summary.id,
                "origin": summary.origin,
                "allowedPathPrefixes": summary.path_prefixes,
                "seedUrls": summary.seed_urls,
                "noticeSha256": summary.notice.sha256,
                "permissions": permissions,
                "expiresAtMs": summary.expires_at_ms,
                "lifecycle": source.get("lifecycle"),
                "policyExpired": source.get("policyExpiredAtStatusTime"),
                "retentionExpired": source.get("retentionExpiredAtStatusTime"),
                "requestBudget": requests,
                "frontierStateCounts": source.get("frontierStateCounts"),
                "dueWorkCount": source.get("dueWorkCount"),
                "nextDueMs": source.get("nextDueMs"),
                "currentlyIndexedLiveUrls": source.get("currentlyIndexedLiveUrls"),
                "removedFrontierUrls": source.get("removedFrontierUrls"),
                "pendingOutboxCount": source.get("pendingOutboxCount"),
                "rejectedOutboxCount": source.get("rejectedOutboxCount"),
            },
            "coverageDefinition": "currently indexed live URLs are the durable frontier/index intersection; this is not a claim of full site coverage",
        }))
    }

    pub(crate) fn policy_binding_is_current(&self) -> Result<(), String> {
        self.load_bound_policy().map(|_| ())
    }

    pub(crate) fn run(&self, request_count: usize) -> Result<crate::PublicCrawlOutput, String> {
        let policy = self.current_run_policy_at(now_ms())?;
        crate::run_public_crawl(
            &policy,
            &self.store,
            &self.frontier,
            request_count,
            &self.manifest.policy_sha256,
            true,
        )
        .map_err(|error| format!("workspace crawl failed: {error}"))
    }

    #[cfg(test)]
    fn run_with_owned_fixture_for_test(
        &self,
        request_count: usize,
        fixture: crate::safe_fetch::OwnedFixtureTls,
        now_ms: u64,
    ) -> Result<crate::PublicCrawlOutput, String> {
        let policy = self.current_run_policy_at(now_ms)?;
        crate::run_public_crawl_with_owned_fixture(
            &policy,
            &self.store,
            &self.frontier,
            request_count,
            &self.manifest.policy_sha256,
            fixture,
            now_ms,
        )
        .map_err(|error| format!("workspace crawl failed: {error}"))
    }

    fn current_run_policy_at(&self, now_ms: u64) -> Result<PublicCrawlPolicy, String> {
        let policy = self.load_bound_policy()?;
        let summary = policy
            .site_source_summary()
            .map_err(|_| "workspace policy must identify exactly one source".to_owned())?;
        let visible_until_ms = PersistentIndex::open(&self.store)
            .and_then(|store| store.public_collection_visibility_deadline_ms())
            .map_err(|_| "workspace public collection admission is unavailable".to_owned())?
            .ok_or_else(|| "workspace public collection admission is unavailable".to_owned())?;
        let policy_expired = summary.expires_at_ms <= now_ms;
        let retention_expired = !policy_expired && visible_until_ms <= now_ms;
        if policy_expired || retention_expired {
            controlled_crawler::revoke_public_source(
                &self.store,
                &self.frontier,
                &self.manifest.source_id,
            )
            .map_err(|error| {
                format!("expired workspace source could not be revoked locally: {error}")
            })?;
            let reason = if policy_expired {
                "policy expired"
            } else {
                "retention period expired"
            };
            return Err(format!(
                "workspace {reason}; source was revoked locally without network access"
            ));
        }
        policy
            .validate_for_crawl(now_ms)
            .map_err(|error| format!("workspace policy is not current: {error}"))?;
        Ok(policy)
    }

    pub(crate) fn revoke(&self) -> Result<String, String> {
        crate::revoke_public_source(&self.store, &self.frontier, &self.manifest.source_id)
            .map_err(|_| "workspace source could not be revoked".to_owned())?;
        serde_json::to_string_pretty(&json!({
            "schema": "ley-site-revocation-v1",
            "sourceId": self.manifest.source_id,
            "revoked": true,
            "frontierOutboxTextCleared": true,
            "physicalErasureGuaranteed": false,
            "immutableStoreGenerationsAndBackupsMayRetainBytes": true,
        }))
        .map_err(|_| "could not serialize revocation status".to_owned())
    }
}

pub(crate) fn run_cli(args: &[String]) -> Result<SiteCommandOutput, String> {
    let Some(action) = args.first().map(String::as_str) else {
        return Err("site requires init, run, status, or revoke".to_owned());
    };
    match action {
        "init" => init_cli(&args[1..]),
        "run" => run_cli_action(&args[1..]),
        "status" => status_cli(&args[1..]),
        "revoke" => revoke_cli(&args[1..]),
        _ => Err("site requires init, run, status, or revoke".to_owned()),
    }
}

pub(crate) fn selected_store_path(workspace_path: impl AsRef<Path>) -> Result<PathBuf, String> {
    let workspace = SiteWorkspace::open(workspace_path)?;
    workspace.load_bound_policy()?;
    Ok(workspace.store.clone())
}

fn init_cli(args: &[String]) -> Result<SiteCommandOutput, String> {
    let mut destination = None;
    let mut policy_path = None;
    let mut digest = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--workspace" if destination.is_none() => destination = next_value(args, &mut index),
            "--policy" if policy_path.is_none() => policy_path = next_value(args, &mut index),
            "--approved-policy-sha256" if digest.is_none() => digest = next_value(args, &mut index),
            _ => {
                return Err(format!(
                    "unknown or repeated site init argument: {:?}",
                    args[index]
                ));
            }
        }
        index += 1;
    }
    let (Some(destination), Some(policy_path), Some(digest)) = (destination, policy_path, digest)
    else {
        return Err("site init requires --workspace NEW_DIR, --policy PATH, and --approved-policy-sha256 HASH".to_owned());
    };
    let policy = PublicCrawlPolicy::load_approved(&policy_path, &digest)
        .map_err(|error| format!("site policy validation failed: {error}"))?;
    policy
        .validate_for_crawl(now_ms())
        .map_err(|error| format!("site policy is not current: {error}"))?;
    let summary = policy
        .site_source_summary()
        .map_err(|_| "site workspaces require exactly one approved source".to_owned())?;
    let root = new_workspace_path(Path::new(&destination))?;
    if fs::symlink_metadata(&root).is_ok() {
        return Err("workspace already exists; init never reuses or overwrites it".to_owned());
    }
    let policy_path = canonical_policy_path(Path::new(&policy_path))?;
    let stage = create_private_stage(&root)?;
    let mut cleanup = StageCleanup(Some(stage.clone()));
    let store = stage.join("store");
    let frontier = stage.join("frontier.sqlite");
    controlled_crawler::initialize_public_collection(&store, &frontier, &policy)
        .map_err(|error| format!("offline workspace initialization failed: {error}"))?;
    let index = PersistentIndex::open(&store)
        .map_err(|_| "offline workspace index could not be reopened".to_owned())?;
    let manifest = WorkspaceManifest {
        schema: WORKSPACE_SCHEMA.to_owned(),
        policy_path,
        policy_sha256: policy.sha256(),
        source_id: summary.id.clone(),
        store_identity: hex(&index.store_identity()),
        created_at_ms: now_ms(),
    };
    drop(index);
    write_manifest(&stage.join(MANIFEST_FILE), &manifest)?;
    let initial_status = verify_staged_workspace(&stage)?;
    let parent = root
        .parent()
        .ok_or_else(|| "workspace destination has no parent".to_owned())?;
    crate::storage::rename_directory_noreplace(&stage, &root).map_err(|_| {
        "workspace destination appeared or could not be published atomically".to_owned()
    })?;
    cleanup.0 = None;
    sync_directory(parent)?;
    Ok(SiteCommandOutput {
        json: serde_json::to_string_pretty(&json!({
            "schema": "ley-site-workspace-init-v1",
            "backend": "controlled_crawler",
            "policySha256": manifest.policy_sha256,
            "networkRequests": 0,
            "source": summary,
            "rightsNote": "Policy fields and the stored notice are operator evidence. Ley does not independently establish legal rights or permission.",
            "initialStatus": initial_status,
        }))
        .map_err(|_| "could not serialize workspace initialization".to_owned())?,
        success: true,
    })
}

fn run_cli_action(args: &[String]) -> Result<SiteCommandOutput, String> {
    let mut workspace_path = None;
    let mut request_count = None;
    let mut allow_public_requests = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--workspace" if workspace_path.is_none() => {
                workspace_path = next_value(args, &mut index)
            }
            "--requests" if request_count.is_none() => {
                request_count =
                    next_value(args, &mut index).and_then(|value| value.parse::<usize>().ok());
            }
            "--allow-public-requests" if !allow_public_requests => allow_public_requests = true,
            _ => {
                return Err(format!(
                    "unknown or repeated site run argument: {:?}",
                    args[index]
                ));
            }
        }
        index += 1;
    }
    if !allow_public_requests {
        return Err("site run requires the explicit --allow-public-requests opt-in".to_owned());
    }
    let Some(workspace_path) = workspace_path else {
        return Err("site run requires --workspace PATH".to_owned());
    };
    let Some(request_count @ 1..=MAX_PUBLIC_REQUESTS_PER_RUN) = request_count else {
        return Err(format!(
            "site run --requests must be between 1 and {MAX_PUBLIC_REQUESTS_PER_RUN}"
        ));
    };
    let workspace = SiteWorkspace::open(workspace_path)?;
    let result = workspace.run(request_count)?;
    Ok(SiteCommandOutput {
        json: result.report_json,
        success: true,
    })
}

fn status_cli(args: &[String]) -> Result<SiteCommandOutput, String> {
    let workspace = parse_workspace_arg(args, "site status")?;
    let workspace = SiteWorkspace::open(workspace)?;
    Ok(SiteCommandOutput {
        json: workspace.status_json()?,
        success: true,
    })
}

fn revoke_cli(args: &[String]) -> Result<SiteCommandOutput, String> {
    let workspace = parse_workspace_arg(args, "site revoke")?;
    let workspace = SiteWorkspace::open(workspace)?;
    Ok(SiteCommandOutput {
        json: workspace.revoke()?,
        success: true,
    })
}

fn parse_workspace_arg(args: &[String], command: &str) -> Result<String, String> {
    if args.len() != 2 || args[0] != "--workspace" {
        return Err(format!("{command} requires only --workspace PATH"));
    }
    Ok(args[1].clone())
}

fn next_value(args: &[String], index: &mut usize) -> Option<String> {
    *index += 1;
    args.get(*index).cloned()
}

fn new_workspace_path(path: &Path) -> Result<PathBuf, String> {
    let absolute = absolute_without_parent(path)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| "workspace destination must have an existing parent directory".to_owned())?;
    let name = absolute
        .file_name()
        .ok_or_else(|| "workspace destination must name a new directory".to_owned())?;
    if name.is_empty() || name == "." || name == ".." {
        return Err("workspace destination must name a new directory".to_owned());
    }
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| "workspace parent directory must already exist".to_owned())?;
    if canonical_parent != parent {
        return Err("workspace path may not traverse a symbolic-link parent".to_owned());
    }
    validate_workspace_parent_chain(&canonical_parent)?;
    Ok(canonical_parent.join(name))
}

fn existing_private_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let absolute = absolute_without_parent(path)?;
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|_| format!("{label} does not exist or is unavailable"))?;
    if !metadata.file_type().is_dir() {
        return Err(format!("{label} must be a real directory, not a symlink"));
    }
    require_private_owner(&metadata, label)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!("{label} permissions must be private (0700)"));
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| format!("{label} has no parent directory"))?;
    validate_workspace_parent_chain(parent)?;
    let canonical =
        fs::canonicalize(&absolute).map_err(|_| format!("{label} could not be resolved"))?;
    if canonical != absolute {
        return Err(format!("{label} path may not traverse a symbolic link"));
    }
    Ok(canonical)
}

fn validate_workspace_parent_chain(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| "workspace parent directory chain is unavailable".to_owned())?;
        if !metadata.file_type().is_dir() {
            return Err("workspace parent directory chain contains a non-directory".to_owned());
        }
        let mode = metadata.permissions().mode();
        if !workspace_parent_is_safe(mode, metadata.uid(), unsafe { libc::geteuid() }) {
            return Err(
                "workspace parent is writable by other users without trusted sticky-bit ownership"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn workspace_parent_is_safe(mode: u32, owner_uid: u32, operator_uid: u32) -> bool {
    mode & 0o022 == 0 || (mode & 0o1000 != 0 && (owner_uid == 0 || owner_uid == operator_uid))
}

fn absolute_without_parent(path: &Path) -> Result<PathBuf, String> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "current directory is unavailable".to_owned())?
            .join(path)
    };
    let mut absolute = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(prefix) => absolute.push(prefix.as_os_str()),
            Component::RootDir => absolute.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err("workspace paths may not contain parent traversal".to_owned());
            }
            Component::Normal(name) => absolute.push(name),
        }
    }
    if !absolute.is_absolute() {
        return Err("workspace path must resolve to an absolute location".to_owned());
    }
    Ok(absolute)
}

fn create_private_stage(destination: &Path) -> Result<PathBuf, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "workspace destination has no parent".to_owned())?;
    let name = destination
        .file_name()
        .ok_or_else(|| "workspace destination has no directory name".to_owned())?
        .to_string_lossy();
    for attempt in 0..10 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let stage = parent.join(format!(
            ".{name}.ley-stage-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&stage) {
            Ok(()) => return Ok(stage),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err("could not create a private workspace staging directory".to_owned());
            }
        }
    }
    Err("could not reserve a unique private workspace staging directory".to_owned())
}

fn write_manifest(path: &Path, manifest: &WorkspaceManifest) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|_| "could not encode workspace manifest".to_owned())?;
    if bytes.len() > MANIFEST_MAX_BYTES {
        return Err("workspace manifest exceeds its size limit".to_owned());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "could not create a private workspace manifest".to_owned())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "could not persist workspace manifest".to_owned())?;
    Ok(())
}

fn verify_staged_workspace(root: &Path) -> Result<Value, String> {
    let workspace = SiteWorkspace::open(root)?;
    let status: Value = serde_json::from_str(&workspace.status_json()?)
        .map_err(|_| "staged crawl state is malformed".to_owned())?;
    let crawl = &status["crawl"];
    let source = crawl
        .get("sources")
        .and_then(Value::as_array)
        .and_then(|sources| sources.first())
        .ok_or_else(|| "staged source admission is missing".to_owned())?;
    if source["persistentRequests"]["persistentUsed"] != 0
        || source["persistentRequests"]["persistentLimit"]
            .as_u64()
            .is_none()
        || source["dueWorkCount"].as_u64().unwrap_or(0) == 0
    {
        return Err("staged source admission did not seed an unused bounded frontier".to_owned());
    }
    Ok(json!({
        "persistentRequests": source["persistentRequests"],
        "frontierStateCounts": source["frontierStateCounts"],
        "dueWorkCount": source["dueWorkCount"],
        "currentlyIndexedLiveUrls": source["currentlyIndexedLiveUrls"],
    }))
}

fn canonical_policy_path(path: &Path) -> Result<PathBuf, String> {
    let canonical =
        fs::canonicalize(path).map_err(|_| "policy path could not be resolved".to_owned())?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|_| "policy path could not be inspected".to_owned())?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err("policy file must be a regular unlinked file".to_owned());
    }
    Ok(canonical)
}

fn validate_manifest(manifest: &WorkspaceManifest) -> Result<(), String> {
    if manifest.schema != WORKSPACE_SCHEMA
        || !valid_sha256(&manifest.policy_sha256)
        || !valid_store_identity(&manifest.store_identity)
        || manifest.source_id.is_empty()
        || manifest.source_id.len() > 128
        || !manifest
            .source_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !manifest.policy_path.is_absolute()
        || manifest
            .policy_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("workspace manifest fields are invalid".to_owned());
    }
    Ok(())
}

fn read_private_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let before =
        fs::symlink_metadata(path).map_err(|_| "workspace manifest is unavailable".to_owned())?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        return Err("workspace manifest must be a regular unlinked file".to_owned());
    }
    require_private_owner(&before, "workspace manifest")?;
    if before.permissions().mode() & 0o077 != 0 || before.len() as usize > maximum {
        return Err("workspace manifest permissions or size are invalid".to_owned());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "workspace manifest could not be opened safely".to_owned())?;
    let opened = file
        .metadata()
        .map_err(|_| "workspace manifest could not be inspected".to_owned())?;
    if !opened.file_type().is_file() || opened.dev() != before.dev() || opened.ino() != before.ino()
    {
        return Err("workspace manifest changed while it was opened".to_owned());
    }
    let mut reader = file.take(maximum as u64 + 1);
    let mut bytes = Vec::with_capacity(before.len() as usize);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| "workspace manifest could not be read".to_owned())?;
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| "workspace manifest could not be rechecked".to_owned())?;
    if bytes.len() > maximum || after.len() != before.len() || bytes.len() as u64 != before.len() {
        return Err("workspace manifest changed or exceeded its size limit".to_owned());
    }
    Ok(bytes)
}

fn require_owned_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("{label} is unavailable"))?;
    if !metadata.file_type().is_dir() {
        return Err(format!("{label} must be a real directory"));
    }
    require_private_owner(&metadata, label)
}

fn require_owned_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("{label} is unavailable"))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(format!(
            "{label} must be a regular unlinked file, not a symlink"
        ));
    }
    require_private_owner(&metadata, label)
}

fn require_private_owner(metadata: &fs::Metadata, label: &str) -> Result<(), String> {
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(format!("{label} must be owned by the current operator"));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "workspace parent directory could not be synced".to_owned())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_store_identity(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

struct StageCleanup(Option<PathBuf>);

impl Drop for StageCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}

impl crate::public_policy::SitePermissionSummary {
    fn fetch_granted(&self) -> bool {
        self.fetch.granted()
    }

    fn storage_granted(&self) -> bool {
        self.storage.granted()
    }

    fn index_granted(&self) -> bool {
        self.index.granted()
    }

    fn display_granted(&self) -> bool {
        self.display.granted()
    }
}

#[cfg(test)]
mod tests {
    use super::{SiteWorkspace, hex, workspace_parent_is_safe};
    use crate::safe_fetch::tls_test_support::{Fixture, Response};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    const QUESTION_V1: &str = "cobalt compass cedar shelf";
    const QUESTION_V2: &str = "amber compass cedar shelf";
    const REDIRECT_QUESTION: &str = "copper signal flag";

    fn evidence_root() -> PathBuf {
        let root = PathBuf::from(
            std::env::var_os("LEY_SITE_E2E_ROOT")
                .expect("LEY_SITE_E2E_ROOT must name a new private evidence directory"),
        );
        assert!(root.is_absolute(), "evidence root must be absolute");
        fs::create_dir(&root).expect("evidence root must not already exist");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn ley_binary() -> PathBuf {
        let path = PathBuf::from(
            std::env::var_os("LEY_SITE_E2E_BIN").expect("LEY_SITE_E2E_BIN must name ley"),
        );
        assert!(path.is_absolute(), "ley binary path must be absolute");
        assert!(path.is_file(), "ley binary must exist");
        path
    }

    fn harness_path() -> PathBuf {
        let path = PathBuf::from(
            std::env::var_os("LEY_SITE_E2E_HARNESS")
                .expect("LEY_SITE_E2E_HARNESS must name the private client harness"),
        );
        assert!(path.is_absolute() && path.is_file());
        path
    }

    fn run_ley(binary: &Path, args: &[&str]) -> Output {
        Command::new(binary)
            .args(args)
            .output()
            .expect("candidate ley process must start")
    }

    fn json_stdout(output: &Output) -> Value {
        assert!(
            output.status.success(),
            "ley exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("ley must return JSON")
    }

    fn status_counts(status: &Value) -> (u64, u64, u64) {
        let source = &status["crawl"]["sources"][0];
        (
            source["persistentRequests"]["persistentUsed"]
                .as_u64()
                .expect("persistent request use"),
            source["persistentRequests"]["persistentRemaining"]
                .as_u64()
                .expect("persistent request remainder"),
            source["currentlyIndexedLiveUrls"]
                .as_u64()
                .expect("currently indexed live URL count"),
        )
    }

    #[test]
    fn writable_sticky_workspace_parents_must_have_a_trusted_owner() {
        assert!(workspace_parent_is_safe(0o1777, 0, 1000));
        assert!(workspace_parent_is_safe(0o1777, 1000, 1000));
        assert!(!workspace_parent_is_safe(0o1777, 1001, 1000));
        assert!(!workspace_parent_is_safe(0o0777, 0, 1000));
        assert!(workspace_parent_is_safe(0o0755, 1001, 1000));
    }

    fn has_ready_or_due_work_at(
        workspace: &SiteWorkspace,
        root: &Path,
        phase: &str,
        attempt: u64,
        now_ms: u64,
    ) -> bool {
        let clock_path = root.join(format!("{phase}-clock-{attempt}.json"));
        save_json(
            &clock_path,
            &json!({
                "schema": "ley-fixture-clock-v1",
                "now_ms": now_ms,
                "time_basis": "fixture-logical"
            }),
        );
        let status = crate::crawl_status_json(
            &workspace.store,
            &workspace.frontier,
            Some("owned-site-workflow-fixture"),
            Some(&clock_path),
            true,
        )
        .unwrap();
        let status: Value = serde_json::from_str(&status).unwrap();
        let source = &status["sources"][0];
        source["dueWorkCount"].as_u64().unwrap() > 0
            || source["frontierStateCounts"]["ready"].as_u64().unwrap_or(0) > 0
            || source["frontierUrlInventory"]
                .as_array()
                .unwrap()
                .iter()
                .any(|frontier| {
                    frontier["state"] == "complete" && frontier["dueMs"].as_u64().unwrap() <= now_ms
                })
    }

    fn evidence_reference(response: &Value, path: &str) -> Value {
        response["hits"]
            .as_array()
            .expect("retrieval hits")
            .iter()
            .find(|hit| {
                hit["requested_url"]
                    .as_str()
                    .is_some_and(|url| url.ends_with(path))
            })
            .unwrap_or_else(|| panic!("retrieval did not find {path}"))["passage"]["reference"]
            .clone()
    }

    fn query(binary: &Path, workspace: &Path, question: &str) -> Value {
        json_stdout(&run_ley(
            binary,
            &[
                "retrieve",
                "--workspace",
                workspace.to_str().unwrap(),
                "--question",
                question,
            ],
        ))
    }

    fn resolve(binary: &Path, workspace: &Path, root: &Path, reference: &Value) -> Output {
        let input_path = root.join("reference.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&input_path)
            .expect("reference evidence file must be new");
        serde_json::to_writer(&mut file, reference).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
        let output = run_ley(
            binary,
            &[
                "resolve-evidence",
                "--workspace",
                workspace.to_str().unwrap(),
                "--reference-file",
                input_path.to_str().unwrap(),
            ],
        );
        fs::remove_file(input_path).unwrap();
        output
    }

    fn permission(reviewed_at_ms: u64) -> Value {
        json!({
            "granted": true,
            "basis": "owned authored offline fixture only",
            "evidence": "synthetic test input; no real public permission is represented",
            "reviewed_at_ms": reviewed_at_ms,
        })
    }

    fn routes(version_two: bool) -> BTreeMap<String, Response> {
        let mut robots = Response::text(
            "User-agent: LeyBot\nAllow: /manual/\nDisallow: /manual/robots-denied.html\n",
        );
        robots
            .headers
            .push(("cache-control".to_owned(), "max-age=3600".to_owned()));
        let child = if version_two {
            "<title>Keeper field notes</title><p>The field keeper stores an amber compass beneath the cedar shelf.</p>"
        } else {
            "<title>Keeper field notes</title><p>The field keeper stores a cobalt compass beneath the cedar shelf.</p>"
        };
        let retired = if version_two {
            Response::body(410, "text/plain", b"retired".to_vec())
        } else {
            Response::html(
                "<title>Old ledger</title><p>An obsolete violet ledger remains in the archive.</p>",
            )
        };
        BTreeMap::from([
            ("/robots.txt".to_owned(), robots),
            (
                "/manual/start.html".to_owned(),
                Response::html(
                    "<title>Field manual</title><p>The navigation manual records the dawn bell protocol.</p><a href='/manual/child.html'>Keeper notes</a><a href='/manual/redirect.html'>Redirected notes</a><a href='/manual/retired.html'>Old ledger</a><a href='/manual/robots-denied.html'>Blocked record</a><a href='/private/outside.html'>Private route</a><a href='/manual/escape.html'>Redirect escape</a>",
                ),
            ),
            ("/manual/child.html".to_owned(), Response::html(child)),
            (
                "/manual/redirect.html".to_owned(),
                Response::redirect("/manual/final.html"),
            ),
            (
                "/manual/final.html".to_owned(),
                Response::html(
                    "<title>Redirected section</title><p>The redirected section records a copper signal flag.</p>",
                ),
            ),
            ("/manual/retired.html".to_owned(), retired),
            (
                "/manual/robots-denied.html".to_owned(),
                Response::html(
                    "<title>Blocked record</title><p>deniedrouteuniquemarker must never be indexed.</p>",
                ),
            ),
            (
                "/private/outside.html".to_owned(),
                Response::html(
                    "<title>Private boundary</title><p>privateboundaryuniquemarker cobalt compass.</p>",
                ),
            ),
            (
                "/manual/unlinked.html".to_owned(),
                Response::html(
                    "<title>Unlinked record</title><p>unlinkedroutespecialmarker zinc sextant stays undiscovered.</p>",
                ),
            ),
            (
                "/manual/escape.html".to_owned(),
                Response::redirect("https://redirect-target.example.invalid/private"),
            ),
        ])
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn save_json(path: &Path, value: &Value) {
        write_private(
            path,
            format!("{}\n", serde_json::to_string_pretty(value).unwrap()).as_bytes(),
        );
    }

    fn current_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn max_rss_kib() -> u64 {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        assert_eq!(result, 0);
        let usage = unsafe { usage.assume_init() };
        u64::try_from(usage.ru_maxrss).expect("maximum RSS must be nonnegative")
    }

    fn process_cpu_micros() -> (u64, u64) {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        assert_eq!(result, 0);
        let usage = unsafe { usage.assume_init() };
        let micros = |time: libc::timeval| {
            u64::try_from(time.tv_sec)
                .unwrap()
                .saturating_mul(1_000_000)
                .saturating_add(u64::try_from(time.tv_usec).unwrap())
        };
        (micros(usage.ru_utime), micros(usage.ru_stime))
    }

    #[test]
    #[ignore = "requires the explicit private owned-loopback CLI, HTTP, MCP, and Chromium harness"]
    fn owned_tls_site_workspace_crawls_and_serves_the_same_evidence() {
        let started = Instant::now();
        let root = evidence_root();
        let binary = ley_binary();
        let host = "owned-site-fixture.example.invalid";
        let fixture = Fixture::start(host, routes(false));
        let port = fixture.address.port();
        let origin = format!("https://{host}:{port}");
        let now = current_time_ms();
        let notice = b"Authored offline fixture text only. No public source or legal permission is represented.\n";
        let notice_path = root.join("source-notice.txt");
        let policy_path = root.join("policy.json");
        write_private(&notice_path, notice);
        let notice_sha = hex(&Sha256::digest(notice));
        let permission = permission(now.saturating_sub(1));
        let policy = json!({
            "schema": "ley-public-sources-v2",
            "enabled": true,
            "identity": "LeyBot/0.1",
            "contact": "https://github.com/example/ley-offline-fixture",
            "sources": [{
                "id": "owned-site-workflow-fixture",
                "origin": origin,
                "path_prefixes": ["/manual/"],
                "seeds": [format!("{origin}/manual/start.html")],
                "fetch_permission": permission,
                "storage_permission": permission,
                "index_permission": permission,
                "display_permission": permission,
                "license": "authored fixture text; no external license claim",
                "source_version": "owned-site-fixture-v1",
                "notice_file": "source-notice.txt",
                "notice_sha256": notice_sha,
                "robots": "obey",
                "removal_contact": "https://github.com/example/ley-offline-fixture",
                "retention_days": 2,
                "expires_at_ms": now.saturating_add(30 * DAY_MS),
                "max_requests": 32,
                "min_origin_delay_ms": 1000,
                "max_wire_bytes": 4_194_304,
                "max_decoded_bytes": 16_777_216
            }]
        });
        let policy_bytes = format!("{}\n", serde_json::to_string_pretty(&policy).unwrap());
        let policy_sha = hex(&Sha256::digest(policy_bytes.as_bytes()));
        write_private(&policy_path, policy_bytes.as_bytes());
        let checked_in_policy_sha = hex(&Sha256::digest(include_bytes!(
            "../policy/public-sources.json"
        )));
        assert_eq!(
            checked_in_policy_sha,
            "8d6b44bdd829a7e1b4e1df612fcd59d4f19107031f3702e877989327fb262972"
        );
        let workspace_path = root.join("workspace");
        let init = json_stdout(&run_ley(
            &binary,
            &[
                "site",
                "init",
                "--workspace",
                workspace_path.to_str().unwrap(),
                "--policy",
                policy_path.to_str().unwrap(),
                "--approved-policy-sha256",
                &policy_sha,
            ],
        ));
        assert_eq!(init["networkRequests"], 0);
        assert_eq!(init["policySha256"], policy_sha);
        assert!(
            init["rightsNote"]
                .as_str()
                .unwrap()
                .contains("does not independently establish legal rights")
        );
        assert!(
            fixture.requests().is_empty(),
            "site init must not contact the fixture"
        );
        assert!(
            !run_ley(
                &binary,
                &[
                    "site",
                    "run",
                    "--workspace",
                    workspace_path.to_str().unwrap(),
                    "--requests",
                    "1",
                ],
            )
            .status
            .success(),
            "networking requires the existing explicit opt-in"
        );
        assert!(
            fixture.requests().is_empty(),
            "a rejected run must send no requests"
        );

        let crawler_started = Instant::now();
        let crawl_now = current_time_ms();
        let workspace = SiteWorkspace::open(&workspace_path).unwrap();
        let partial = workspace
            .run_with_owned_fixture_for_test(1, fixture.owned_transport(), crawl_now)
            .unwrap();
        let partial_report: Value = serde_json::from_str(&partial.report_json).unwrap();
        assert_eq!(
            partial_report["counts"]["requests"], 1,
            "{partial_report:#}"
        );
        assert_eq!(fixture.requests(), vec!["/robots.txt"]);

        let partial_status = json_stdout(&run_ley(
            &binary,
            &[
                "site",
                "status",
                "--workspace",
                workspace_path.to_str().unwrap(),
            ],
        ));
        let (used_after_partial, remaining_after_partial, indexed_after_partial) =
            status_counts(&partial_status);
        assert_eq!(used_after_partial, 1);
        assert_eq!(remaining_after_partial, 31);
        assert_eq!(indexed_after_partial, 0);
        drop(workspace);

        let mut resume_reports = Vec::new();
        let mut resume_pending_work = true;
        for attempt in 1..=12u64 {
            let workspace = SiteWorkspace::open(&workspace_path).unwrap();
            let run_now = crawl_now.saturating_add(attempt.saturating_mul(1000));
            let resumed = workspace
                .run_with_owned_fixture_for_test(1, fixture.owned_transport(), run_now)
                .unwrap();
            let report: Value = serde_json::from_str(&resumed.report_json).unwrap();
            assert!(report["counts"]["requests"].as_u64().unwrap() <= 1);
            assert_eq!(
                report["boundedRunFinished"],
                report["stopReason"] == "frontier_idle"
            );
            resume_pending_work =
                has_ready_or_due_work_at(&workspace, &root, "resume", attempt, run_now);
            resume_reports.push(report);
            drop(workspace);
            if !resume_pending_work {
                break;
            }
        }
        assert!(
            !resume_pending_work,
            "bounded resume calls must clear ready and currently due work"
        );
        let resume_report = resume_reports.last().unwrap().clone();
        assert!(
            resume_reports
                .iter()
                .map(|report| report["counts"]["requests"].as_u64().unwrap())
                .sum::<u64>()
                > 0
        );
        let resumed_status = json_stdout(&run_ley(
            &binary,
            &[
                "site",
                "status",
                "--workspace",
                workspace_path.to_str().unwrap(),
            ],
        ));
        let (used_after_resume, _, indexed_after_resume) = status_counts(&resumed_status);
        assert!(used_after_resume > used_after_partial);
        assert!(indexed_after_resume >= 3);
        assert!(
            resumed_status["crawl"]["sources"][0]["latestRetryOrFailureEvents"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["urlKey"]
                    .as_str()
                    .is_some_and(|url| url.ends_with("/manual/escape.html")))
        );

        let old_child = query(&binary, &workspace_path, QUESTION_V1);
        assert_eq!(old_child["answer_assessment"], "not_assessed");
        let old_child_reference = evidence_reference(&old_child, "/manual/child.html");
        let old_retired = query(&binary, &workspace_path, "obsolete violet ledger");
        let old_retired_reference = evidence_reference(&old_retired, "/manual/retired.html");
        let redirected = query(&binary, &workspace_path, REDIRECT_QUESTION);
        let redirect_hit = redirected["hits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|hit| {
                hit["requested_url"]
                    .as_str()
                    .is_some_and(|url| url.ends_with("/manual/redirect.html"))
            })
            .expect("redirected passage must keep its requested identity");
        assert!(
            redirect_hit["effective_url"]
                .as_str()
                .unwrap()
                .ends_with("/manual/final.html")
        );
        let redirect_reference = redirect_hit["passage"]["reference"].clone();
        let resolved_redirect = json_stdout(&resolve(
            &binary,
            &workspace_path,
            &root,
            &redirect_reference,
        ));
        assert_eq!(resolved_redirect["text"], redirect_hit["passage"]["text"]);

        for forbidden_question in [
            "deniedrouteuniquemarker",
            "privateboundaryuniquemarker",
            "unlinkedroutespecialmarker",
        ] {
            let result = query(&binary, &workspace_path, forbidden_question);
            assert!(
                result["hits"].as_array().unwrap().is_empty(),
                "{forbidden_question} must remain unindexed"
            );
        }

        let requests_after_v1 = fixture.requests();
        for required in [
            "/manual/start.html",
            "/manual/child.html",
            "/manual/redirect.html",
            "/manual/final.html",
            "/manual/retired.html",
            "/manual/escape.html",
        ] {
            assert!(
                requests_after_v1.iter().any(|path| path == required),
                "fixture did not receive {required}"
            );
        }
        for forbidden in [
            "/manual/robots-denied.html",
            "/private/outside.html",
            "/manual/unlinked.html",
            "/private",
        ] {
            assert!(
                requests_after_v1.iter().all(|path| path != forbidden),
                "forbidden route was requested: {forbidden}"
            );
        }

        fixture.replace_routes(routes(true));
        let recrawl_at = crawl_now.saturating_add(25 * 60 * 60 * 1000);
        let mut update_reports = Vec::new();
        let mut update_pending_work = true;
        for attempt in 1..=12u64 {
            let workspace = SiteWorkspace::open(&workspace_path).unwrap();
            let run_now = recrawl_at.saturating_add(attempt.saturating_mul(1000));
            let updated = workspace
                .run_with_owned_fixture_for_test(1, fixture.owned_transport(), run_now)
                .unwrap();
            let report: Value = serde_json::from_str(&updated.report_json).unwrap();
            assert!(report["counts"]["requests"].as_u64().unwrap() <= 1);
            assert_eq!(
                report["boundedRunFinished"],
                report["stopReason"] == "frontier_idle"
            );
            update_pending_work =
                has_ready_or_due_work_at(&workspace, &root, "update", attempt, run_now);
            update_reports.push(report);
            drop(workspace);
            if !update_pending_work {
                break;
            }
        }
        assert!(
            !update_pending_work,
            "bounded recrawl calls must clear ready and currently due work"
        );
        let update_report = update_reports.last().unwrap().clone();
        assert!(
            update_reports
                .iter()
                .map(|report| report["counts"]["requests"].as_u64().unwrap())
                .sum::<u64>()
                > 0
        );
        let crawler_elapsed_ms = crawler_started.elapsed().as_millis();

        let current_child = query(&binary, &workspace_path, QUESTION_V2);
        assert_eq!(current_child["answer_assessment"], "not_assessed");
        let current_child_reference = evidence_reference(&current_child, "/manual/child.html");
        assert!(
            current_child["hits"][0]["passage"]["text"]
                .as_str()
                .unwrap()
                .contains("amber compass")
        );
        let stale_child = resolve(&binary, &workspace_path, &root, &old_child_reference);
        assert!(!stale_child.status.success());
        assert!(String::from_utf8_lossy(&stale_child.stderr).contains("version_superseded"));
        let removed_retired = resolve(&binary, &workspace_path, &root, &old_retired_reference);
        assert!(!removed_retired.status.success());
        assert!(String::from_utf8_lossy(&removed_retired.stderr).contains("not_live"));

        let final_status = json_stdout(&run_ley(
            &binary,
            &[
                "site",
                "status",
                "--workspace",
                workspace_path.to_str().unwrap(),
            ],
        ));
        assert_eq!(final_status["policySha256"], policy_sha);
        assert_eq!(final_status["source"]["origin"], origin);
        assert_eq!(final_status["source"]["notice"]["sha256"], notice_sha);
        let (used_after_recrawl, remaining_after_recrawl, indexed_after_recrawl) =
            status_counts(&final_status);
        assert!(
            used_after_recrawl > used_after_partial,
            "resume and recrawl must preserve and increase the persisted budget"
        );
        assert_eq!(used_after_recrawl + remaining_after_recrawl, 32);
        assert!(
            indexed_after_recrawl >= 3,
            "known live indexed URLs should remain visible after removal"
        );
        assert_eq!(final_status["source"]["pathPrefixes"][0], "/manual/");
        save_json(&root.join("site-status-final.json"), &final_status);
        let fixture_peers = fixture.accepted_peers();
        assert!(!fixture_peers.is_empty());
        assert!(fixture_peers.iter().all(|peer| peer.ip().is_loopback()));
        let connected_destinations = [&partial_report["connectedDestinations"]]
            .into_iter()
            .flat_map(|destinations| destinations.as_array().unwrap())
            .chain(
                resume_reports
                    .iter()
                    .flat_map(|report| report["connectedDestinations"].as_array().unwrap().iter()),
            )
            .chain(
                update_reports
                    .iter()
                    .flat_map(|report| report["connectedDestinations"].as_array().unwrap().iter()),
            )
            .collect::<Vec<_>>();
        assert!(!connected_destinations.is_empty());
        let fixture_endpoint = fixture.address.to_string();
        for destination in &connected_destinations {
            assert!(
                destination["requestedUrl"]
                    .as_str()
                    .unwrap()
                    .starts_with(&origin)
            );
            assert_eq!(destination["resolvedAddresses"][0], fixture_endpoint);
            assert_eq!(destination["connectedPeer"], fixture_endpoint);
            assert_eq!(destination["proxyUsed"], false);
        }

        let expected = json!({
            "workspace": workspace_path,
            "origin": origin,
            "policySha256": policy_sha,
            "noticeSha256": notice_sha,
            "question": QUESTION_V2,
            "reference": current_child_reference,
            "redirectQuestion": REDIRECT_QUESTION,
            "redirectReference": redirect_reference,
            "noticeText": String::from_utf8(notice.to_vec()).unwrap(),
            "requestsAfterV1": requests_after_v1,
        });
        save_json(&root.join("client-expectations.json"), &expected);
        let (crawler_user_cpu_micros, crawler_system_cpu_micros) = process_cpu_micros();
        save_json(
            &root.join("crawler-proof.json"),
            &json!({
                "classification": "owned authored offline fixture only; no public website request",
                "policySha256": policy_sha,
                "noticeSha256": notice_sha,
                "init": init,
                "firstBoundedRun": partial_report,
                "statusAfterPartial": partial_status,
                "resumeReport": resume_report,
                "resumeReports": resume_reports,
                "statusAfterResume": resumed_status,
                "updateReport": update_report,
                "updateReports": update_reports,
                "statusAfterUpdate": final_status,
                "fixtureRequests": fixture.requests(),
                "fixtureAcceptedPeers": fixture_peers,
                "fixtureEndpoint": fixture_endpoint,
                "connectedDestinations": connected_destinations,
                "fixtureResponseWireBytes": fixture.response_bytes(),
                "crawlerElapsedMs": crawler_elapsed_ms,
                "testProcessResources": {
                    "userCpuMicros": crawler_user_cpu_micros,
                    "systemCpuMicros": crawler_system_cpu_micros,
                    "maxRssKiB": max_rss_kib(),
                    "scope": "Rust test process; child processes excluded"
                }
            }),
        );

        let requests_before_clients = fixture.requests();
        let harness = Command::new("node")
            .arg(harness_path())
            .env("LEY_SITE_E2E_ROOT", &root)
            .env("LEY_SITE_E2E_BIN", &binary)
            .output()
            .expect("private CLI, HTTP, MCP, and Chromium harness must start");
        assert!(
            harness.status.success(),
            "client harness exited {:?}: {}\n{}",
            harness.status.code(),
            String::from_utf8_lossy(&harness.stdout),
            String::from_utf8_lossy(&harness.stderr)
        );
        let clients: Value = serde_json::from_slice(
            &fs::read(root.join("client-result.json")).expect("client result must be saved"),
        )
        .unwrap();
        assert_eq!(clients["result"], "PASS");
        assert_eq!(
            clients["http"]["retrieval"]["hits"][0]["passage"]["reference"],
            expected["reference"]
        );
        assert_eq!(
            clients["mcp"]["resolved"]["reference"],
            expected["reference"]
        );
        assert!(
            clients["browser"]["jsErrors"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fixture.requests(),
            requests_before_clients,
            "read-only clients must not cause crawler traffic"
        );

        let workspace = SiteWorkspace::open(&workspace_path).unwrap();
        let store = crate::storage::PersistentIndex::open(workspace.store_path()).unwrap();
        let visible_until_ms = store
            .public_collection_visibility_deadline_ms()
            .unwrap()
            .unwrap();
        let policy_expires_at_ms = workspace
            .load_bound_policy()
            .unwrap()
            .site_source_summary()
            .unwrap()
            .expires_at_ms;
        assert!(visible_until_ms < policy_expires_at_ms);
        let retention_error = workspace
            .current_run_policy_at(visible_until_ms)
            .unwrap_err();
        assert!(retention_error.contains("retention period expired"));
        assert!(retention_error.contains("revoked locally without network access"));
        let retention_status: Value =
            serde_json::from_str(&workspace.status_json().unwrap()).unwrap();
        let retention_source = &retention_status["crawl"]["sources"][0];
        assert_eq!(retention_source["lifecycle"], "revoked");
        assert_eq!(retention_source["currentlyIndexedLiveUrls"], 0);
        assert_eq!(retention_source["pendingOutboxCount"], 0);
        assert_eq!(
            retention_source["persistentRequests"]["persistentUsed"],
            used_after_recrawl
        );
        save_json(
            &root.join("site-status-after-retention.json"),
            &retention_status,
        );
        save_json(
            &root.join("retention-expiry.json"),
            &json!({
                "classification": "synthetic future time against owned offline fixture workspace",
                "policyExpiresAtMs": policy_expires_at_ms,
                "authenticatedVisibilityDeadlineMs": visible_until_ms,
                "runPreflightError": retention_error,
                "persistentRequestsUsed": used_after_recrawl,
                "fixtureRequestsAfterClients": fixture.requests(),
                "fixtureRequestsBeforeClients": requests_before_clients,
                "sourceLifecycleAfterCleanup": retention_source["lifecycle"],
                "currentlyIndexedLiveUrlsAfterCleanup": retention_source["currentlyIndexedLiveUrls"],
                "pendingOutboxCountAfterCleanup": retention_source["pendingOutboxCount"],
                "physicalErasureGuaranteed": false
            }),
        );
        drop(store);
        drop(workspace);

        let revoke = json_stdout(&run_ley(
            &binary,
            &[
                "site",
                "revoke",
                "--workspace",
                workspace_path.to_str().unwrap(),
            ],
        ));
        assert_eq!(revoke["revoked"], true);
        let after_revoke = resolve(&binary, &workspace_path, &root, &current_child_reference);
        assert!(!after_revoke.status.success());
        assert!(String::from_utf8_lossy(&after_revoke.stderr).contains("revoked"));

        let (user_cpu_micros, system_cpu_micros) = process_cpu_micros();
        let max_rss_kib = max_rss_kib();
        let report = json!({
            "result": "PASS",
            "classification": "owned offline fixture only; no public permission or public network request",
            "origin": origin,
            "policySha256": policy_sha,
            "noticeSha256": notice_sha,
            "init": init,
            "firstBoundedRun": partial_report,
            "statusAfterPartial": partial_status,
            "resumeReport": resume_report,
            "resumeReports": resume_reports,
            "statusAfterResume": resumed_status,
            "updateReport": update_report,
            "updateReports": update_reports,
            "statusAfterRecrawl": final_status,
            "revocation": revoke,
            "fixtureRequests": fixture.requests(),
            "fixtureAcceptedPeers": fixture_peers,
            "fixtureResponseWireBytes": fixture.response_bytes(),
            "crawlerElapsedMs": crawler_elapsed_ms,
            "endToEndElapsedMs": started.elapsed().as_millis(),
            "testProcessResources": {
                "userCpuMicros": user_cpu_micros,
                "systemCpuMicros": system_cpu_micros,
                "maxRssKiB": max_rss_kib,
                "scope": "Rust test process, including crawler fixture work; child CLI, MCP, API, UI, and Chromium processes are excluded"
            },
            "clients": clients,
            "workspace": workspace_path,
            "publicPolicyFileSha256": checked_in_policy_sha,
        });
        save_json(&root.join("site-to-evidence-e2e.json"), &report);
    }
}
