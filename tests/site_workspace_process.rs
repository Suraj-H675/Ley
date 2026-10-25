#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct TempDirectory(PathBuf);

struct ApiServer(Child);

impl TempDirectory {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ley-site-workspace-test-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ley"))
        .args(args)
        .output()
        .unwrap()
}

fn assert_success(output: Output) -> String {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn assert_failure(output: Output, expected: &str) -> String {
    assert!(!output.status.success(), "command unexpectedly succeeded");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(expected), "unexpected error: {stderr}");
    stderr
}

fn write_test_policy(directory: &Path) -> (PathBuf, String) {
    write_test_policy_with_lifetime(directory, 86_400_000)
}

fn write_test_policy_with_lifetime(directory: &Path, lifetime_ms: u64) -> (PathBuf, String) {
    fs::create_dir_all(directory).unwrap();
    let notice = b"Owned policy-validation fixture. This is not a permission grant.\n";
    let notice_path = directory.join("source-notice.txt");
    fs::write(&notice_path, notice).unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let permission = json!({
        "granted": true,
        "basis": "synthetic test fixture only; no real permission",
        "evidence": "owned validation input; no public request is authorized",
        "reviewed_at_ms": now_ms - 1
    });
    let value = json!({
        "schema": "ley-public-sources-v2",
        "enabled": true,
        "identity": "LeyBot/0.1",
        "contact": "operator@example.org",
        "sources": [{
            "id": "offline-test-source",
            "origin": "https://docs.example.invalid",
            "path_prefixes": ["/manual/"],
            "seeds": ["https://docs.example.invalid/manual/start.html"],
            "fetch_permission": permission,
            "storage_permission": permission,
            "index_permission": permission,
            "display_permission": permission,
            "license": "synthetic test fixture",
            "source_version": "offline-test-v1",
            "notice_file": "source-notice.txt",
            "notice_sha256": hex(&Sha256::digest(notice)),
            "robots": "obey",
            "removal_contact": "operator@example.org",
            "retention_days": 2,
            "expires_at_ms": now_ms + lifetime_ms,
            "max_requests": 12,
            "min_origin_delay_ms": 1000,
            "max_wire_bytes": 4_194_304,
            "max_decoded_bytes": 16_777_216
        }]
    });
    let policy_bytes = serde_json::to_vec_pretty(&value).unwrap();
    let digest = hex(&Sha256::digest(&policy_bytes));
    let policy_path = directory.join("policy.json");
    fs::write(&policy_path, policy_bytes).unwrap();
    (policy_path, digest)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn free_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn start_server(workspace: &Path, address: SocketAddr) -> ApiServer {
    ApiServer(
        Command::new(env!("CARGO_BIN_EXE_ley"))
            .args([
                "serve",
                "--workspace",
                workspace.to_str().unwrap(),
                "--bind",
                &address.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

fn request(address: SocketAddr, request: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, serde_json::from_str(body).unwrap())
}

fn wait_for_server(address: SocketAddr, child: &mut ApiServer) {
    for _ in 0..50 {
        if child.0.try_wait().unwrap().is_some() {
            panic!("workspace API exited before listening");
        }
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("workspace API did not listen on the selected loopback address");
}

impl Drop for ApiServer {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn workspace_init_status_and_http_bind_one_offline_approved_policy() {
    let help = assert_success(command(&["site", "--help"]));
    assert!(help.contains("site init --workspace NEW_DIR"));
    assert!(help.contains("does not establish permission"));
    for action in ["init", "run", "status", "revoke"] {
        let action_help = assert_success(command(&["site", action, "--help"]));
        assert!(action_help.contains("Usage: ley site"));
    }

    let temp = TempDirectory::new();
    let policy_directory = temp.path().join("policy");
    let (policy_path, digest) = write_test_policy(&policy_directory);
    let workspace = temp.path().join("site");

    let init = assert_success(command(&[
        "site",
        "init",
        "--workspace",
        workspace.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--approved-policy-sha256",
        &digest,
    ]));
    let init: Value = serde_json::from_str(&init).unwrap();
    assert_eq!(init["schema"], "ley-site-workspace-init-v1");
    assert_eq!(init["policySha256"], digest);
    assert_eq!(init["networkRequests"], 0);
    assert_eq!(init["source"]["origin"], "https://docs.example.invalid");
    assert_eq!(
        init["source"]["seedUrls"][0],
        "https://docs.example.invalid/manual/start.html"
    );
    assert!(
        init["rightsNote"]
            .as_str()
            .unwrap()
            .contains("establish legal rights")
    );
    assert!(workspace.join("store").is_dir());
    assert!(workspace.join("frontier.sqlite").is_file());

    let status: Value = serde_json::from_str(&assert_success(command(&[
        "site",
        "status",
        "--workspace",
        workspace.to_str().unwrap(),
    ])))
    .unwrap();
    assert_eq!(status["schema"], "ley-site-status-v1");
    assert_eq!(
        status["crawl"]["sources"][0]["persistentRequests"]["persistentUsed"],
        0
    );
    assert_eq!(
        status["crawl"]["sources"][0]["persistentRequests"]["persistentLimit"],
        12
    );

    let same_cli: Value = serde_json::from_str(&assert_success(command(&[
        "retrieve",
        "--workspace",
        workspace.to_str().unwrap(),
        "--question",
        "manual retry window",
    ])))
    .unwrap();
    let raw_store: Value = serde_json::from_str(&assert_success(command(&[
        "retrieve",
        "--store",
        workspace.join("store").to_str().unwrap(),
        "--question",
        "manual retry window",
    ])))
    .unwrap();
    assert_eq!(same_cli, raw_store);
    assert_eq!(same_cli["answer_assessment"], "not_assessed");

    assert_failure(
        command(&[
            "site",
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--requests",
            "1",
        ]),
        "explicit",
    );
    let unchanged: Value = serde_json::from_str(&assert_success(command(&[
        "site",
        "status",
        "--workspace",
        workspace.to_str().unwrap(),
    ])))
    .unwrap();
    assert_eq!(
        unchanged["crawl"]["sources"][0]["persistentRequests"]["persistentUsed"],
        0
    );

    let repeated = command(&[
        "site",
        "init",
        "--workspace",
        workspace.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--approved-policy-sha256",
        &digest,
    ]);
    assert_failure(repeated, "already exists");

    let address = free_loopback_address();
    let mut server = start_server(&workspace, address);
    wait_for_server(address, &mut server);
    let (status_code, body) = request(
        address,
        &format!(
            "GET /api/v1/workspace/status HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(status_code, 200);
    assert_eq!(body["backend"], "controlled_crawler");
    assert_eq!(body["readOnly"], true);
    assert!(body["source"]["allowedPathPrefixes"].as_array().is_some());
    assert_eq!(body["source"]["permissions"]["fetchRecorded"], true);
    assert_eq!(body["source"]["permissions"]["storageRecorded"], true);
    assert_eq!(body["source"]["permissions"]["indexRecorded"], true);
    assert_eq!(body["source"]["permissions"]["displayRecorded"], true);
    assert_eq!(body["source"]["requestBudget"]["persistentUsed"], 0);
    assert!(
        body["source"]["requestBudget"]["persistentCounterSemantics"]
            .as_str()
            .unwrap()
            .contains("robots request reservations")
    );
    assert!(!body.to_string().contains(workspace.to_str().unwrap()));

    let retrieve_body = serde_json::to_vec(&json!({
        "mode": "question",
        "request": {
            "contract_version": 1,
            "question": "manual retry window",
            "max_hits": 8
        }
    }))
    .unwrap();
    let retrieve_request = format!(
        "POST /api/v1/retrieve HTTP/1.1\r\nHost: localhost:{}\r\nOrigin: http://localhost:{}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        address.port(),
        address.port(),
        retrieve_body.len(),
        String::from_utf8(retrieve_body).unwrap()
    );
    let (retrieve_status, http_retrieval) = request(address, &retrieve_request);
    assert_eq!(retrieve_status, 200);
    assert_eq!(http_retrieval, same_cli);
    assert_eq!(http_retrieval["answer_assessment"], "not_assessed");

    let (injection_status, injection_body) = request(
        address,
        &format!(
            "GET /api/v1/workspace/status?path=/etc/passwd HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert_eq!(injection_status, 400);
    assert!(injection_body["error"].is_string());

    server.0.kill().unwrap();
    server.0.wait().unwrap();
}

#[test]
fn workspace_rejects_policy_drift_symlinks_and_explicit_reuse() {
    let temp = TempDirectory::new();
    let policy_directory = temp.path().join("policy");
    let (policy_path, digest) = write_test_policy(&policy_directory);
    let workspace = temp.path().join("site");
    assert_success(command(&[
        "site",
        "init",
        "--workspace",
        workspace.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--approved-policy-sha256",
        &digest,
    ]));

    let hard_link = temp.path().join("frontier-alias.sqlite");
    fs::hard_link(workspace.join("frontier.sqlite"), &hard_link).unwrap();
    assert_failure(
        command(&["site", "status", "--workspace", workspace.to_str().unwrap()]),
        "unlinked",
    );
    fs::remove_file(hard_link).unwrap();

    let manifest_path = workspace.join("workspace.json");
    let original_manifest = fs::read(&manifest_path).unwrap();
    let mut altered_manifest: Value = serde_json::from_slice(&original_manifest).unwrap();
    altered_manifest["policySha256"] = json!("0".repeat(64));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&altered_manifest).unwrap(),
    )
    .unwrap();
    assert_failure(
        command(&["site", "status", "--workspace", workspace.to_str().unwrap()]),
        "protected store admission",
    );
    fs::write(&manifest_path, original_manifest).unwrap();

    let mut policy = fs::read(&policy_path).unwrap();
    policy.push(b' ');
    fs::write(&policy_path, policy).unwrap();
    let drifted_digest = hex(&Sha256::digest(fs::read(&policy_path).unwrap()));
    assert_failure(
        command(&["site", "status", "--workspace", workspace.to_str().unwrap()]),
        "SHA-256",
    );

    let symlink = temp.path().join("site-link");
    std::os::unix::fs::symlink(&workspace, &symlink).unwrap();
    assert_failure(
        command(&["site", "status", "--workspace", symlink.to_str().unwrap()]),
        "symlink",
    );

    let parent_alias = temp.path().join("parent-alias");
    std::os::unix::fs::symlink(temp.path(), &parent_alias).unwrap();
    assert_failure(
        command(&[
            "site",
            "init",
            "--workspace",
            parent_alias.join("new-site").to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--approved-policy-sha256",
            &drifted_digest,
        ]),
        "symbolic-link parent",
    );
}

#[test]
fn workspace_rejects_writable_non_sticky_parents_for_create_and_open() {
    let temp = TempDirectory::new();
    let (policy_path, digest) = write_test_policy(&temp.path().join("policy"));
    let parent = temp.path().join("shared-parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();

    let rejected_workspace = parent.join("rejected");
    assert_failure(
        command(&[
            "site",
            "init",
            "--workspace",
            rejected_workspace.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--approved-policy-sha256",
            &digest,
        ]),
        "writable by other users",
    );
    assert!(!rejected_workspace.exists());

    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let workspace = parent.join("site");
    assert_success(command(&[
        "site",
        "init",
        "--workspace",
        workspace.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--approved-policy-sha256",
        &digest,
    ]));
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert_failure(
        command(&["site", "status", "--workspace", workspace.to_str().unwrap()]),
        "writable by other users",
    );
}

#[test]
fn expired_workspace_run_revokes_pending_text_without_network_access() {
    let temp = TempDirectory::new();
    let (policy_path, digest) = write_test_policy_with_lifetime(&temp.path().join("policy"), 2_000);
    let workspace = temp.path().join("site");
    assert_success(command(&[
        "site",
        "init",
        "--workspace",
        workspace.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--approved-policy-sha256",
        &digest,
    ]));

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let frontier = rusqlite::Connection::open(workspace.join("frontier.sqlite")).unwrap();
    frontier
        .execute(
            "INSERT INTO outbox(url_key,source_id,lease_token,kind,title,body,completion_state,status,created_ms) VALUES (?1,'offline-test-source',zeroblob(32),0,'retention marker','extracted body to clear','complete','pending',?2)",
            ("https://docs.example.invalid/manual/pending.html", now_ms),
        )
        .unwrap();
    drop(frontier);

    thread::sleep(Duration::from_millis(2_100));
    assert_failure(
        command(&[
            "site",
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--requests",
            "1",
            "--allow-public-requests",
        ]),
        "revoked locally without network access",
    );

    let frontier = rusqlite::Connection::open(workspace.join("frontier.sqlite")).unwrap();
    let (lifecycle, retained_text_rows): (String, i64) = frontier
        .query_row(
            "SELECT (SELECT lifecycle FROM source_policy WHERE source_id='offline-test-source'), (SELECT COUNT(*) FROM outbox WHERE source_id='offline-test-source' AND (title IS NOT NULL OR body IS NOT NULL))",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(lifecycle, "revoked");
    assert_eq!(retained_text_rows, 0);

    let status: Value = serde_json::from_str(&assert_success(command(&[
        "site",
        "status",
        "--workspace",
        workspace.to_str().unwrap(),
    ])))
    .unwrap();
    assert_eq!(status["crawl"]["sources"][0]["lifecycle"], "revoked");
    assert_eq!(
        status["crawl"]["sources"][0]["policyExpiredAtStatusTime"],
        true
    );
}
