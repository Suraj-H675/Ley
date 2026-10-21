#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);
const PREFIX: &str = "https://offline.example/guide/";

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ley-managed-process-test-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
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

fn spawn_sync(store: &Path, source: &Path) -> io::Result<Child> {
    Command::new(env!("CARGO_BIN_EXE_ley"))
        .args([
            "local-collection",
            "sync",
            "--store",
            store.to_str().unwrap(),
            "--directory",
            source.to_str().unwrap(),
            "--url-prefix",
            PREFIX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

#[test]
fn cli_restart_and_separate_process_syncs_share_one_serial_collection() -> io::Result<()> {
    let temp = TempDirectory::new();
    let source = temp.path().join("source");
    let store = temp.path().join("index");
    fs::create_dir(&source)?;
    fs::write(
        source.join("one.html"),
        "<html><head><title>One</title></head><body>first offline passage</body></html>",
    )?;
    let init = assert_success(command(&[
        "local-collection",
        "init",
        "--store",
        store.to_str().unwrap(),
        "--directory",
        source.to_str().unwrap(),
        "--url-prefix",
        PREFIX,
    ]));
    assert!(init.contains("added 1"));

    // A new executable process opens the durable owner record and index.
    let status = assert_success(command(&[
        "local-collection",
        "status",
        "--store",
        store.to_str().unwrap(),
    ]));
    assert!(status.contains("state: ready"));
    assert!(status.contains("live documents: 1"));

    fs::write(
        source.join("two.html"),
        "<html><head><title>Two</title></head><body>second offline passage</body></html>",
    )?;
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(store.join(".LOCAL_COLLECTION_LOCK"))?;
    // SAFETY: lock_file owns the descriptor for the collection lock while held.
    assert_eq!(
        unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) },
        0
    );
    let mut first = spawn_sync(&store, &source)?;
    let mut second = match spawn_sync(&store, &source) {
        Ok(child) => child,
        Err(error) => {
            let _ = first.kill();
            let _ = first.wait();
            return Err(error);
        }
    };
    thread::sleep(Duration::from_millis(100));
    let first_waiting = first.try_wait();
    let second_waiting = second.try_wait();
    // SAFETY: unlock the descriptor acquired above; both child processes then serialize on it.
    let unlocked = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN) };
    if unlocked != 0 {
        let _ = first.kill();
        let _ = second.kill();
    }
    drop(lock_file);
    let first_output = first.wait_with_output();
    let second_output = second.wait_with_output();
    assert_eq!(unlocked, 0, "could not release the collection lock");
    assert!(
        matches!(first_waiting, Ok(None)),
        "first sync did not block"
    );
    assert!(
        matches!(second_waiting, Ok(None)),
        "second sync did not block"
    );
    assert_success(first_output?);
    assert_success(second_output?);

    let final_status = assert_success(command(&[
        "local-collection",
        "status",
        "--store",
        store.to_str().unwrap(),
    ]));
    assert!(final_status.contains("generation: 3"));
    assert!(final_status.contains("segments: 2"));
    assert!(final_status.contains("live documents: 2"));
    Ok(())
}
