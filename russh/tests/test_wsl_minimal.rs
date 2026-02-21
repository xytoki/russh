#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! OpenSSH interop verification tests.
//!
//! All tests are `#[ignore]` and only run when explicitly requested.
//! They require a local OpenSSH sshd (e.g. in WSL/Docker) listening on 127.0.0.1:2200
//! with user `russh_test` / password `russh_test`.
//!
//! # Running
//!
//! ```sh
//! # Run all interop tests (will skip unless env var is set):
//! RUSSH_SSHD_INTEROP=1 cargo test -p russh --test test_wsl_minimal -- --ignored
//!
//! # Optionally pin specific host-key fingerprints (comma-separated SHA256:... strings):
//! RUSSH_PINNED_HOSTKEY_FPS=SHA256:xxxx,SHA256:yyyy \
//!   RUSSH_SSHD_INTEROP=1 cargo test -p russh --test test_wsl_minimal -- --ignored
//! ```

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, format_fingerprint_base64};
use russh::*;
use tokio::io::AsyncWriteExt;

const HOST: &str = "127.0.0.1";
const PORT: u16 = 2200;
const USER: &str = "russh_test";
const PASS: &str = "russh_test";

fn require_sshd_interop() -> bool {
    if std::env::var("RUSSH_SSHD_INTEROP").as_deref() != Ok("1") {
        eprintln!("SKIP: set RUSSH_SSHD_INTEROP=1 to run OpenSSH interop tests");
        return false;
    }
    true
}

/// Read `RUSSH_PINNED_HOSTKEY_FPS` env var, returning `None` when unset/empty.
fn pinned_fingerprints_from_env() -> Option<Vec<String>> {
    match std::env::var("RUSSH_PINNED_HOSTKEY_FPS") {
        Ok(val) if !val.is_empty() => {
            Some(val.split(',').map(|s| s.trim().to_string()).collect())
        }
        _ => None,
    }
}

struct TestClient;

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn minimal_preferred() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(&[
            kex::ECDH_SHA2_NISTP256,
            kex::EXTENSION_SUPPORT_AS_CLIENT,
            kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
        ]),
        key: Cow::Borrowed(&[
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
            ssh_key::Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha256),
            },
        ]),
        cipher: Cow::Borrowed(&[cipher::AES_128_GCM, cipher::AES_256_GCM]),
        ..Default::default()
    }
}

/// Build a client config whose pin checker behaviour depends on
/// `RUSSH_PINNED_HOSTKEY_FPS`:
///
/// - **Set**: only accept fingerprints listed in the env var.
/// - **Unset**: accept any fingerprint but record it in `recorder` so the
///   caller can assert the checker actually ran.
fn make_config_with_pinning(
    recorder: Arc<std::sync::Mutex<Option<String>>>,
) -> Arc<client::Config> {
    let checker: Box<dyn Fn(&[u8; 32]) -> bool + Send + Sync> =
        if let Some(allowed) = pinned_fingerprints_from_env() {
            Box::new(move |hash: &[u8; 32]| {
                let fp = format_fingerprint_base64(hash);
                allowed.contains(&fp)
            })
        } else {
            let rec = recorder.clone();
            Box::new(move |hash: &[u8; 32]| {
                let fp = format_fingerprint_base64(hash);
                let mut guard = rec.lock().unwrap();
                *guard = Some(fp);
                true
            })
        };

    Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(10)),
        preferred: minimal_preferred(),
        host_key_pin_checker: Some(checker),
        ..<_>::default()
    })
}

#[ignore]
#[tokio::test]
async fn test_exec_with_pinning() {
    if !require_sshd_interop() { return; }
    let _ = env_logger::try_init();

    let recorder = Arc::new(std::sync::Mutex::new(None));
    let config = make_config_with_pinning(recorder.clone());
    let mut session = client::connect(config, (HOST, PORT), TestClient)
        .await
        .unwrap();

    let auth = session
        .authenticate_password(USER, PASS)
        .await
        .unwrap();
    assert!(auth.success(), "password auth should succeed");

    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();

    let mut output = Vec::new();
    loop {
        let Some(msg) = channel.wait().await else {
            break;
        };
        if let ChannelMsg::Data { ref data } = msg {
            output.extend_from_slice(data);
        }
    }
    let out_str = String::from_utf8_lossy(&output);
    assert!(out_str.trim() == "ok", "exec output should be 'ok', got: {out_str}");

    // When no explicit pins are provided the recorder must have captured a fingerprint.
    if pinned_fingerprints_from_env().is_none() {
        let fp = recorder.lock().unwrap().clone();
        assert!(
            fp.as_ref().is_some_and(|s| !s.is_empty()),
            "pin checker should have recorded a non-empty fingerprint, got: {fp:?}"
        );
    }

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

/// Negative test: a pin checker that rejects everything must cause connection
/// failure. This test does not need any pinned fingerprints.
#[ignore]
#[tokio::test]
async fn test_pinning_rejects_wrong_fingerprint() {
    if !require_sshd_interop() { return; }
    let _ = env_logger::try_init();

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(5)),
        preferred: minimal_preferred(),
        host_key_pin_checker: Some(Box::new(|_hash: &[u8; 32]| {
            false
        })),
        ..<_>::default()
    });

    let result = client::connect(config, (HOST, PORT), TestClient).await;
    assert!(result.is_err(), "connection should fail with wrong pin");
}

#[cfg(not(target_arch = "wasm32"))]
#[ignore]
#[tokio::test]
async fn test_sftp_with_pinning() {
    if !require_sshd_interop() { return; }
    let _ = env_logger::try_init();

    let recorder = Arc::new(std::sync::Mutex::new(None));
    let config = make_config_with_pinning(recorder.clone());
    let mut session = client::connect(config, (HOST, PORT), TestClient)
        .await
        .unwrap();

    let auth = session
        .authenticate_password(USER, PASS)
        .await
        .unwrap();
    assert!(auth.success());

    let channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();

    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .unwrap();

    let cwd = sftp.canonicalize(".").await.unwrap();
    assert!(!cwd.is_empty(), "canonicalize should return a path");

    let test_file = "/tmp/russh_wsl_test_sftp.txt";
    use russh_sftp::protocol::OpenFlags;
    use tokio::io::AsyncReadExt;
    let mut file = sftp
        .open_with_flags(
            test_file,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
        )
        .await
        .unwrap();
    file.write_all(b"sftp_ok").await.unwrap();
    file.flush().await.unwrap();
    file.shutdown().await.unwrap();

    let mut file2 = sftp
        .open_with_flags(test_file, OpenFlags::READ)
        .await
        .unwrap();
    let mut buf = String::new();
    file2.read_to_string(&mut buf).await.unwrap();
    assert_eq!(buf, "sftp_ok");
    file2.shutdown().await.unwrap();

    sftp.remove_file(test_file).await.unwrap();

    // Verify the recorder captured a fingerprint when no explicit pins given.
    if pinned_fingerprints_from_env().is_none() {
        let fp = recorder.lock().unwrap().clone();
        assert!(
            fp.as_ref().is_some_and(|s| !s.is_empty()),
            "pin checker should have recorded a non-empty fingerprint"
        );
    }

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[ignore]
#[tokio::test]
async fn test_local_port_forward_with_pinning() {
    if !require_sshd_interop() { return; }
    let _ = env_logger::try_init();

    let recorder = Arc::new(std::sync::Mutex::new(None));
    let config = make_config_with_pinning(recorder.clone());
    let mut session = client::connect(config, (HOST, PORT), TestClient)
        .await
        .unwrap();

    let auth = session
        .authenticate_password(USER, PASS)
        .await
        .unwrap();
    assert!(auth.success());

    let channel = session
        .channel_open_direct_tcpip("127.0.0.1", PORT as u32, "127.0.0.1", 0)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    stream
        .write_all(b"SSH-2.0-test_fwd\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 256];
    use tokio::io::AsyncReadExt;
    let timeout = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    match timeout {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]);
            assert!(
                response.starts_with("SSH-"),
                "forwarded connection should get SSH banner, got: {response}"
            );
        }
        _ => {
            panic!("should receive SSH banner from forwarded port");
        }
    }

    // Verify the recorder captured a fingerprint when no explicit pins given.
    if pinned_fingerprints_from_env().is_none() {
        let fp = recorder.lock().unwrap().clone();
        assert!(
            fp.as_ref().is_some_and(|s| !s.is_empty()),
            "pin checker should have recorded a non-empty fingerprint"
        );
    }

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[ignore]
#[tokio::test]
async fn test_fingerprint_computation() {
    if !require_sshd_interop() { return; }
    let _ = env_logger::try_init();

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(10)),
        preferred: minimal_preferred(),
        ..<_>::default()
    });

    struct FingerprintCapture(std::sync::Arc<std::sync::Mutex<Option<String>>>);

    impl client::Handler for FingerprintCapture {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            server_public_key: &ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            let fp = client::compute_host_key_fingerprint_sha256(server_public_key);
            let fp_str = format_fingerprint_base64(&fp);
            let mut guard = self.0.lock().unwrap();
            *guard = Some(fp_str);
            Ok(true)
        }
    }

    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let handler = FingerprintCapture(captured.clone());

    let mut session = client::connect(config, (HOST, PORT), handler)
        .await
        .unwrap();

    let auth = session
        .authenticate_password(USER, PASS)
        .await
        .unwrap();
    assert!(auth.success());

    let fp = captured.lock().unwrap().clone().unwrap();

    // If explicit pins are given, verify the computed fingerprint is among them.
    // Otherwise just assert a non-empty SHA256 fingerprint was produced.
    if let Some(allowed) = pinned_fingerprints_from_env() {
        assert!(
            allowed.contains(&fp),
            "fingerprint {fp} should match one of the pinned values: {allowed:?}"
        );
    } else {
        assert!(
            fp.starts_with("SHA256:") && fp.len() > 7,
            "fingerprint should be a non-empty SHA256:... string, got: {fp}"
        );
    }

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}
