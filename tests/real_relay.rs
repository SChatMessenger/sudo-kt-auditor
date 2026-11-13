//! The auditor against the real relay (released sudo-relay v0.5.0, development
//! build) on a fresh test database: devices join over several epochs and the
//! auditor checks every one of them through §10.14, then picks up later epochs.
//!
//! Needs PostgreSQL at DATABASE_URL (sudo-relay's compose.yaml).

mod common;
use common::Must;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use sudo_kt_auditor::{Failure, Store, run};
use sudo_relay::api::{self, Relay};
use sudo_relay::auth::ServerName;
use sudo_relay::{Clock, PgPool};

const T0: u64 = 1_767_229_200;
const HEAD_SEED: [u8; 32] = [0x4b; 32];

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Server {
    url: String,
    clock: Arc<TestClock>,
    pool: PgPool,
    relay: Arc<Relay>,
}

async fn start(pool: PgPool) -> Server {
    sudo_relay::migrate(&pool).await.must();
    let clock = Arc::new(TestClock(AtomicU64::new(T0)));
    let mut relay = Relay::unshared(
        pool.clone(),
        ServerName::new("relay.test").must(),
        clock.clone(),
    );
    let keys = sudo_relay::kt::KtKeys {
        head: sudo_crypto::IdentityKey::from_seed(&HEAD_SEED),
        vrf_seed: sudo_crypto::Zeroizing::new([0x56; 32]),
    };
    relay.kt = Some(
        sudo_relay::kt::Directory::open(pool.clone(), keys, T0)
            .await
            .must(),
    );
    let relay = Arc::new(relay);
    let app = api::router(relay.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.must();
    let addr: SocketAddr = listener.local_addr().must();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Server {
        url: format!("http://{addr}"),
        clock,
        pool,
        relay,
    }
}

impl Server {
    /// A new account with one device, published in the next epoch.
    async fn join(&self, user: &str, n: u8) -> u64 {
        let now = self.clock.0.fetch_add(60, Ordering::SeqCst) + 60;
        sqlx::query("INSERT INTO accounts (username, created_at) VALUES ($1, 0)")
            .bind(user)
            .execute(&self.pool)
            .await
            .must();
        let ik = sudo_crypto::IdentityKey::from_seed(&[n; 32]).public();
        sudo_relay::prekeys::add_device(&self.pool, user, &[n; 16], &ik, now)
            .await
            .must();
        let kt = self.relay.kt.as_ref().must();
        kt.publish(now).await.must().must()
    }
}

fn head_key() -> [u8; 32] {
    sudo_crypto::IdentityKey::from_seed(&HEAD_SEED).public()
}

fn state_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "sudo-kt-auditor-real-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .must()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[sqlx::test(migrations = false)]
async fn the_real_relay_passes_every_epoch(pool: PgPool) {
    let s = start(pool).await;
    let store = Store::open(&state_dir("pass")).must();
    // Before any epoch the relay has nothing to show (404).
    assert!(matches!(
        run(&s.url, &head_key(), &store, s.clock.now()).await,
        Err(Failure::Status(404))
    ));
    assert_eq!(s.join("alice", 1).await, 1);
    assert_eq!(s.join("bob", 2).await, 2);
    assert_eq!(s.join("carol", 3).await, 3);
    let started = std::time::Instant::now();
    let r = run(&s.url, &head_key(), &store, s.clock.now()).await.must();
    assert_eq!(r.checked, Some((1, 3)));
    // Paced under the relay's limit of 600 a minute (§10.14).
    assert!(started.elapsed() >= sudo_kt_auditor::PACE * 2);
    assert_eq!(r.latest.0, 3);
    // Later epochs continue from the stored root.
    assert_eq!(s.join("dave", 4).await, 4);
    let r = run(&s.url, &head_key(), &store, s.clock.now()).await.must();
    assert_eq!(r.checked, Some((4, 4)));
    assert_eq!(store.checked().must().len(), 4);
}

#[sqlx::test(migrations = false)]
async fn the_wrong_head_key_is_refused(pool: PgPool) {
    let s = start(pool).await;
    s.join("alice", 1).await;
    let store = Store::open(&state_dir("wrong-key")).must();
    let other = sudo_crypto::IdentityKey::from_seed(&[9; 32]).public();
    let r = run(&s.url, &other, &store, s.clock.now()).await;
    assert!(matches!(r, Err(Failure::Evidence { .. })), "{r:?}");
    assert!(store.checked().must().is_empty());
}

/// The program itself, as people and scripts run it: exit 0 when every proof
/// verifies, 2 when the relay broke a rule (evidence kept), 1 otherwise.
#[sqlx::test(migrations = false)]
async fn the_program_exit_codes(pool: PgPool) {
    let s = start(pool).await;
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .must()
        .as_secs();
    s.clock.0.store(real_now - 60, Ordering::SeqCst);
    s.join("alice", 1).await;
    let state = state_dir("program");
    let program = |key: &str, state: &std::path::Path| {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_sudo-kt-auditor"));
        c.args(["--relay", &s.url, "--head-key", key, "--state"]);
        c.arg(state);
        c
    };
    let good = hex(&head_key());
    let out = exec(program(&good, &state)).await;
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("checked epochs 1 to 1"));
    let out = exec(program(&good, &state)).await;
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("nothing new"));
    let other = hex(&sudo_crypto::IdentityKey::from_seed(&[9; 32]).public());
    let out = exec(program(&other, &state_dir("program-other"))).await;
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("THE RELAY BROKE A RULE"));
    let out = exec(program("abc", &state)).await;
    assert_eq!(out.status.code(), Some(1), "a bad key is a usage error");
    let mut far = program(&good, &state);
    far.args(["--relay", "http://example.com:80"]);
    let out = exec(far).await;
    assert_eq!(out.status.code(), Some(1), "only relays on this computer");
}

/// Runs the program without blocking the relay it talks to.
async fn exec(mut c: std::process::Command) -> std::process::Output {
    tokio::task::spawn_blocking(move || c.output())
        .await
        .must()
        .must()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
