//! The auditor against a fake relay serving the published vectors
//! (kt-directory.json), honestly or not. Every dishonest answer must stop
//! the run with evidence (repo CLAUDE.md: fail loudly).

mod common;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use common::Must;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use sudo_kt::{HEAD_LEN, SignedHead};
use sudo_kt_auditor::{Failure, Store, run};

/// The vectors' pinned SHA-256 (sudo-protocol manifest.json, bundle 4701b4c7…).
const KT_DIRECTORY_SHA256: &str =
    "59ac026ebadf7ce02412bbc7490c3282b83bc60b1ea9d63e646e4497dca2cbbc";
const KT_HEAD_SHA256: &str = "bbd16fbdb06fa1de9f9336b62363c39fabb5f8d98cba4eb90ad7eb32b62d6b90";
/// vectorgen's directory signs epoch e at T0 + 60 e.
const T0: u64 = 1_767_229_200;
const NOW: u64 = T0 + 180;

fn file(name: &str, sha: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    let bytes = std::fs::read(&p).must();
    assert_eq!(
        hex(&sudo_crypto::sha256(&bytes)),
        sha,
        "{name} is the pinned file"
    );
    serde_json::from_slice(&bytes).must()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).must())
        .collect()
}

struct Vectors {
    head_key: [u8; 32],
    head_seed: [u8; 32],
    /// The §10.14 answer for epochs 1, 2, 3.
    audits: HashMap<u64, Vec<u8>>,
}

fn vectors() -> Vectors {
    let v = file("kt-directory.json", KT_DIRECTORY_SHA256);
    let h = file("kt-head.json", KT_HEAD_SHA256);
    let audits = v
        .get("audits")
        .must()
        .as_array()
        .must()
        .iter()
        .enumerate()
        .map(|(i, c)| {
            (
                i as u64 + 1,
                unhex(c.get("response").must().as_str().must()),
            )
        })
        .collect();
    Vectors {
        head_key: unhex(v.get("head_public_key").must().as_str().must())
            .try_into()
            .must(),
        head_seed: unhex(h.get("head_seed").must().as_str().must())
            .try_into()
            .must(),
        audits,
    }
}

/// What the fake relay serves; changeable between runs.
#[derive(Clone, Default)]
struct Fake {
    latest: Vec<u8>,
    audits: HashMap<u64, Vec<u8>>,
}

type Shared = Arc<Mutex<Fake>>;

async fn latest(State(f): State<Shared>) -> Response {
    f.lock().must().latest.clone().into_response()
}

async fn audit(State(f): State<Shared>, Path(e): Path<u64>) -> Response {
    match f.lock().must().audits.get(&e) {
        Some(b) => b.clone().into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve(fake: Fake) -> (String, Shared) {
    let shared = Arc::new(Mutex::new(fake));
    let app = Router::new()
        .route("/v1/kt/latest", get(latest))
        .route("/v1/kt/audit/{e}", get(audit))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.must();
    let addr: SocketAddr = listener.local_addr().must();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), shared)
}

fn honest(v: &Vectors) -> Fake {
    Fake {
        latest: v.audits.get(&3).must().get(..HEAD_LEN).must().to_vec(),
        audits: v.audits.clone(),
    }
}

fn state_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "sudo-kt-auditor-{name}-{}-{}",
        std::process::id(),
        NOW
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// A head signed with the vectors' head key (as a dishonest relay could).
fn signed_head(v: &Vectors, epoch: u64, root: [u8; 32], t: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&epoch.to_be_bytes());
    b.extend_from_slice(&root);
    b.extend_from_slice(&t.to_be_bytes());
    b.extend_from_slice(&t.to_be_bytes());
    let input = SignedHead::parse(&[b.as_slice(), &[0; 64]].concat())
        .must()
        .signature_input();
    b.extend_from_slice(&sudo_crypto::IdentityKey::from_seed(&v.head_seed).sign(&input));
    b
}

fn evidence_of(r: Result<sudo_kt_auditor::Report, Failure>) -> String {
    match r {
        Err(Failure::Evidence { what, evidence }) => {
            assert!(evidence.exists(), "the relay's answer is kept");
            what
        }
        other => panic!("expected evidence, got {other:?}"),
    }
}

#[tokio::test]
async fn an_honest_relay_passes_and_runs_continue() {
    let v = vectors();
    let mut first_two = honest(&v);
    first_two.latest = v.audits[&2][..HEAD_LEN].to_vec();
    first_two.audits.remove(&3);
    let (url, shared) = serve(first_two).await;
    let dir = state_dir("honest");
    let store = Store::open(&dir).must();
    let r = run(&url, &v.head_key, &store, T0 + 120).await.must();
    assert_eq!(r.checked, Some((1, 2)));
    let again = run(&url, &v.head_key, &store, T0 + 120).await.must();
    assert_eq!(again.checked, None, "nothing new");
    // Epoch 3 appears: only it is checked, from the stored root.
    *shared.lock().must() = honest(&v);
    let r = run(&url, &v.head_key, &store, NOW).await.must();
    assert_eq!(r.checked, Some((3, 3)));
    assert_eq!(store.checked().must().len(), 3);
}

#[tokio::test]
async fn a_forged_signature_is_caught() {
    let v = vectors();
    let mut f = honest(&v);
    f.audits.get_mut(&2).must()[HEAD_LEN - 1] ^= 1;
    let (url, _) = serve(f).await;
    let store = Store::open(&state_dir("forged")).must();
    let what = evidence_of(run(&url, &v.head_key, &store, NOW).await);
    assert!(what.contains("signature"), "{what}");
    assert_eq!(store.checked().must().len(), 1, "epoch 1 was fine");
}

#[tokio::test]
async fn another_epochs_answer_is_caught() {
    let v = vectors();
    let mut f = honest(&v);
    let e2 = f.audits[&2].clone();
    f.audits.insert(3, e2);
    let (url, _) = serve(f).await;
    let store = Store::open(&state_dir("wrong-epoch")).must();
    let what = evidence_of(run(&url, &v.head_key, &store, NOW).await);
    assert!(what.contains("another epoch"), "{what}");
}

#[tokio::test]
async fn a_rewritten_proof_is_caught() {
    let v = vectors();
    let mut f = honest(&v);
    // Epoch 2's head with epoch 3's proof: a proof that does not lead from
    // root 1 to root 2.
    let mut mixed = f.audits[&2][..HEAD_LEN].to_vec();
    mixed.extend_from_slice(&f.audits[&3][HEAD_LEN..]);
    f.audits.insert(2, mixed);
    let (url, _) = serve(f).await;
    let store = Store::open(&state_dir("rewritten")).must();
    let what = evidence_of(run(&url, &v.head_key, &store, NOW).await);
    assert!(what.contains("append-only proof"), "{what}");
}

#[tokio::test]
async fn a_shrinking_log_is_caught() {
    let v = vectors();
    let (url, shared) = serve(honest(&v)).await;
    let store = Store::open(&state_dir("shrink")).must();
    run(&url, &v.head_key, &store, NOW).await.must();
    // Later the relay claims epoch 2 is its latest.
    shared.lock().must().latest = v.audits[&2][..HEAD_LEN].to_vec();
    let what = evidence_of(run(&url, &v.head_key, &store, NOW).await);
    assert!(what.contains("shrank"), "{what}");
}

#[tokio::test]
async fn a_second_directory_is_caught() {
    let v = vectors();
    let (url, shared) = serve(honest(&v)).await;
    let store = Store::open(&state_dir("fork")).must();
    run(&url, &v.head_key, &store, NOW).await.must();
    // The relay signs a different root for epoch 3 (a split view, §6.4).
    shared.lock().must().latest = signed_head(&v, 3, [7; 32], NOW);
    let what = evidence_of(run(&url, &v.head_key, &store, NOW).await);
    assert!(what.contains("two directories"), "{what}");
    // And a different history for later epochs: the proof from the stored
    // root fails.
    let mut later = honest(&v);
    later.latest = signed_head(&v, 4, [8; 32], NOW);
    later.audits.insert(
        4,
        [
            signed_head(&v, 4, [8; 32], NOW),
            later.audits[&3][HEAD_LEN..].to_vec(),
        ]
        .concat(),
    );
    *shared.lock().must() = later;
    let what = evidence_of(run(&url, &v.head_key, &store, NOW).await);
    assert!(what.contains("append-only proof"), "{what}");
}

#[tokio::test]
async fn a_stale_latest_head_is_caught() {
    let v = vectors();
    let (url, _) = serve(honest(&v)).await;
    let store = Store::open(&state_dir("stale")).must();
    // A frozen relay, or this computer's clock is wrong: its own exit code,
    // the head kept, nothing recorded.
    match run(&url, &v.head_key, &store, NOW + 3600).await {
        Err(Failure::StaleHead { evidence }) => {
            assert!(evidence.join("latest-head.bin").exists());
        }
        other => panic!("expected a stale head, got {other:?}"),
    }
    assert!(store.checked().must().is_empty());
}

#[tokio::test]
async fn a_hidden_epoch_is_caught() {
    let v = vectors();
    let mut f = honest(&v);
    f.audits.remove(&2);
    let (url, _) = serve(f).await;
    let store = Store::open(&state_dir("hidden")).must();
    let what = evidence_of(run(&url, &v.head_key, &store, NOW).await);
    assert!(what.contains("no proof for epoch 2"), "{what}");
    assert_eq!(store.checked().must().len(), 1);
}

#[tokio::test]
async fn an_edited_state_log_is_refused() {
    let v = vectors();
    let (url, shared) = serve(honest(&v)).await;
    let dir = state_dir("edited");
    let store = Store::open(&dir).must();
    shared.lock().must().latest = v.audits.get(&2).must().get(..HEAD_LEN).must().to_vec();
    run(&url, &v.head_key, &store, NOW).await.must();
    // Change one digit of epoch 2's root: the line no longer matches its head.
    let log = dir.join("heads.log");
    let text = std::fs::read_to_string(&log).must();
    let (first, second) = text.split_once('\n').must();
    let mut second = second.to_owned();
    let digit = if second.as_bytes().get(2) == Some(&b'0') {
        "1"
    } else {
        "0"
    };
    second.replace_range(2..3, digit);
    std::fs::write(&log, format!("{first}\n{second}")).must();
    *shared.lock().must() = honest(&v);
    assert!(matches!(
        run(&url, &v.head_key, &store, NOW).await,
        Err(Failure::State(_))
    ));
    // The same log used with another relay's key is refused too.
    std::fs::write(&log, text).must();
    let other = sudo_crypto::IdentityKey::from_seed(&[9; 32]).public();
    assert!(matches!(
        run(&url, &other, &store, NOW).await,
        Err(Failure::State(_))
    ));
}

#[tokio::test]
async fn another_relays_key_is_refused() {
    let v = vectors();
    let (url, _) = serve(honest(&v)).await;
    let store = Store::open(&state_dir("other-key")).must();
    let other = sudo_crypto::IdentityKey::from_seed(&[9; 32]).public();
    let what = evidence_of(run(&url, &other, &store, NOW).await);
    assert!(what.contains("signature"), "{what}");
    assert!(store.checked().must().is_empty());
}
