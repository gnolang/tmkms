//! KMS integration test

use chrono::{DateTime, Utc};
use cometbft_p2p::{self as p2p, IdentitySecret, PublicKey, ReadMsg, SecretConnection, WriteMsg};
use rand::Rng;
use signature::Verifier;
use std::{
    fs::{self, File},
    io::{self, Cursor, Write},
    net::{TcpListener, TcpStream},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    process::{Child, Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};
use tempfile::{NamedTempFile, TempDir};
use tmkms::{
    config::provider::KeyType,
    connection::Connection,
    connection::unix::UnixConnection,
    keyring::ed25519,
    privval::{ConsensusMsg, ConsensusMsgType},
    proto,
};

/// Integration tests for the KMS command-line interface
mod cli;

/// Path to the KMS executable
const KMS_EXE_PATH: &str = "target/debug/tmkms";

/// Path to the example validator signing key
const SIGNING_ED25519_KEY_PATH: &str = "tests/support/signing_ed25519.key";
const SIGNING_SECP256K1_KEY_PATH: &str = "tests/support/signing_secp256k1.key";

/// Path to the KMS's identity key for the secret connection
const SECRET_CONNECTION_KEY_PATH: &str = "tests/support/secret_connection.key";

/// Name of the KMS's log inside the KMS's directory
const KMS_LOG_FILE: &str = "kms.log";

/// How long a KMS may take to connect, answer or exit before its test fails instead
/// of hanging
const KMS_TIMEOUT: Duration = Duration::from_secs(10);

enum KmsSocket {
    /// TCP socket type
    Tcp(TcpStream),

    /// UNIX socket type
    Unix(UnixStream),
}

enum KmsConnection {
    /// Secret connection type, boxed: it is far larger than the UNIX variant
    Tcp(Box<SecretConnection<TcpStream>>),

    /// UNIX connection type
    Unix(UnixConnection<UnixStream>),
}

impl Connection for KmsConnection {}

impl ReadMsg<proto::privval::Message> for KmsConnection {
    fn read_msg(&mut self) -> p2p::Result<proto::privval::Message> {
        match self {
            KmsConnection::Tcp(conn) => conn.read_msg(),
            KmsConnection::Unix(conn) => conn.read_msg(),
        }
    }
}

impl WriteMsg<proto::privval::Message> for KmsConnection {
    fn write_msg(&mut self, msg: &proto::privval::Message) -> p2p::Result<()> {
        match self {
            KmsConnection::Tcp(conn) => conn.write_msg(msg),
            KmsConnection::Unix(conn) => conn.write_msg(msg),
        }
    }
}

/// Receives incoming KMS connection then sends commands
struct KmsProcess {
    /// KMS child process
    process: Child,

    /// A socket to KMS process
    socket: KmsSocket,

    /// Directory holding this process's keys, double-sign protection state file and
    /// log, kept alive (and cleaned up) for the lifetime of the process
    kms_dir: TempDir,
}

impl KmsProcess {
    /// Spawn the KMS process and wait for an incoming TCP connection
    pub fn create_tcp(key_type: &KeyType) -> Self {
        // Generate a random port and a config file
        let port: u16 = rand::thread_rng().gen_range(60000..=65535);
        let kms_dir = tempfile::tempdir().unwrap();
        let config = KmsProcess::create_tcp_config(port, key_type, &kms_dir);

        // Listen on a random port
        let listener = TcpListener::bind(format!("{}:{}", "127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();

        let mut process = KmsProcess::spawn(&config, &kms_dir);

        let socket = wait_for_connection(&mut process, &kms_dir, || {
            listener.accept().map(|(socket, _)| socket)
        });
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(KMS_TIMEOUT)).unwrap();
        Self {
            process,
            socket: KmsSocket::Tcp(socket),
            kms_dir,
        }
    }

    /// Spawn the KMS process and connect to the Unix listener
    pub fn create_unix(key_type: &KeyType) -> Self {
        Self::create_unix_with(key_type, |_| ())
    }

    /// Like `create_unix`, with `prepare` changing the KMS's directory before the KMS starts
    fn create_unix_with(key_type: &KeyType, prepare: impl FnOnce(&Path)) -> Self {
        // Create a random socket path and a config file
        let mut rng = rand::thread_rng();
        let letter: char = rng.gen_range(b'a'..=b'z') as char;
        let number: u32 = rng.gen_range(0..=999999);
        let socket_path = format!("/tmp/tmkms-{letter}{number:06}.sock");
        let kms_dir = tempfile::tempdir().unwrap();
        let config = KmsProcess::create_unix_config(&socket_path, key_type, &kms_dir);
        prepare(kms_dir.path());

        // Start listening for connections via the Unix socket
        let listener = UnixListener::bind(socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();

        // Fire up the KMS process and allow it to connect to our Unix socket
        let mut process = KmsProcess::spawn(&config, &kms_dir);

        let socket = wait_for_connection(&mut process, &kms_dir, || {
            listener.accept().map(|(socket, _)| socket)
        });
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(KMS_TIMEOUT)).unwrap();
        Self {
            process,
            socket: KmsSocket::Unix(socket),
            kms_dir,
        }
    }

    /// Start a KMS on `config`, logging to a file in `kms_dir` for the test to check.
    /// It logs only warnings and errors, so a healthy KMS logs nothing.
    fn spawn(config: &NamedTempFile, kms_dir: &TempDir) -> Child {
        let log = File::create(kms_dir.path().join(KMS_LOG_FILE)).unwrap();

        Command::new(KMS_EXE_PATH)
            .args(["start", "-c", config.path().to_str().unwrap()])
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap()
    }

    /// Everything the KMS has logged so far
    fn log(&self) -> String {
        kms_log(&self.kms_dir)
    }

    /// Wait for the KMS to exit on its own, and return how it exited
    fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + KMS_TIMEOUT;
        loop {
            if let Some(status) = self.process.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "KMS still running after {KMS_TIMEOUT:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Stop the KMS and return everything it logged
    fn stop(&mut self) -> String {
        self.process.kill().unwrap();
        self.process.wait().unwrap();
        self.log()
    }

    /// Create a config file for a TCP KMS and return its path
    fn create_tcp_config(port: u16, key_type: &KeyType, kms_dir: &TempDir) -> NamedTempFile {
        let mut config_file = NamedTempFile::new().unwrap();
        let pub_key = test_ed25519_signing_keypair().verifying_key();
        let peer_id = PublicKey::from(pub_key).peer_id();
        let state_path = seeded_state_file(kms_dir);
        let secret_key = owner_only_copy(SECRET_CONNECTION_KEY_PATH, kms_dir);
        let signing_key = owner_only_copy(signing_key_path(key_type), kms_dir);

        writeln!(
            config_file,
            r#"
            [[chain]]
            id = "test_chain_id"
            key_format = {{ type = "bech32", account_key_prefix = "cosmospub", consensus_key_prefix = "cosmosvalconspub" }}
            state_file = "{state_path}"

            [[validator]]
            addr = "tcp://{peer_id}@127.0.0.1:{port}"
            chain_id = "test_chain_id"
            max_height = "500000"
            reconnect = false
            secret_key = "{secret_key}"

            [[providers.softsign]]
            chain_ids = ["test_chain_id"]
            key_format = "base64"
            path = "{signing_key}"
            key_type = "{key_type}"
        "#
        ).unwrap();

        config_file
    }

    /// Create a config file for a UNIX KMS and return its path
    fn create_unix_config(
        socket_path: &str,
        key_type: &KeyType,
        kms_dir: &TempDir,
    ) -> NamedTempFile {
        let mut config_file = NamedTempFile::new().unwrap();
        let key_path = owner_only_copy(signing_key_path(key_type), kms_dir);
        let state_path = seeded_state_file(kms_dir);
        writeln!(
            config_file,
            r#"
            [[chain]]
            id = "test_chain_id"
            key_format = {{ type = "bech32", account_key_prefix = "cosmospub", consensus_key_prefix = "cosmosvalconspub" }}
            state_file = "{state_path}"

            [[validator]]
            addr = "unix://{socket_path}"
            chain_id = "test_chain_id"
            max_height = "500000"
            reconnect = false

            [[providers.softsign]]
            chain_ids = ["test_chain_id"]
            key_format = "base64"
            path = "{key_path}"
            key_type = "{key_type}"
        "#
        )
            .unwrap();

        config_file
    }

    /// Get a connection from the socket
    pub fn create_connection(&self) -> KmsConnection {
        match self.socket {
            KmsSocket::Tcp(ref sock) => {
                // we use the same key for both sides:
                let identity_key = IdentitySecret::from(test_ed25519_identity_keypair());

                // Here we reply to the kms with a "remote" ephemeral key, auth signature etc:
                let socket_cp = sock.try_clone().unwrap();

                KmsConnection::Tcp(Box::new(
                    SecretConnection::new(socket_cp, &identity_key).unwrap(),
                ))
            }

            KmsSocket::Unix(ref sock) => {
                let socket_cp = sock.try_clone().unwrap();

                KmsConnection::Unix(UnixConnection::new(socket_cp))
            }
        }
    }
}

impl Drop for KmsProcess {
    fn drop(&mut self) {
        self.process.kill().unwrap();
        self.process.wait().unwrap();

        // The test harness prints this with the failure, so a failing test shows what
        // its KMS logged
        if thread::panicking() {
            eprintln!("--- {KMS_LOG_FILE} ---\n{}", self.log());
        }
    }
}

/// Everything the KMS keeping its files in `kms_dir` has logged so far
fn kms_log(kms_dir: &TempDir) -> String {
    fs::read_to_string(kms_dir.path().join(KMS_LOG_FILE)).unwrap()
}

/// Wait for the KMS to connect, polling `accept` on a non-blocking listener. A KMS that
/// exits first, or doesn't connect within `KMS_TIMEOUT`, fails the test with its log.
fn wait_for_connection<S>(
    process: &mut Child,
    kms_dir: &TempDir,
    mut accept: impl FnMut() -> io::Result<S>,
) -> S {
    let deadline = Instant::now() + KMS_TIMEOUT;

    loop {
        match accept() {
            Ok(socket) => return socket,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
            Err(e) => panic!("couldn't accept the KMS's connection: {e}"),
        }

        let failure = match process.try_wait().unwrap() {
            Some(status) => format!("KMS exited ({status}) before connecting"),
            None if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            None => {
                process.kill().unwrap();
                process.wait().unwrap();
                format!("KMS didn't connect within {KMS_TIMEOUT:?}")
            }
        };
        panic!("{failure}\n--- {KMS_LOG_FILE} ---\n{}", kms_log(kms_dir));
    }
}

/// A struct to hold protocol integration tests contexts
struct ProtocolTester {
    tcp_device: KmsProcess,
    tcp_connection: KmsConnection,
    unix_device: KmsProcess,
    unix_connection: KmsConnection,
}

impl ProtocolTester {
    /// Start a TCP and a UNIX KMS and connect to both
    pub fn start(key_type: &KeyType) -> Self {
        let tcp_device = KmsProcess::create_tcp(key_type);
        let tcp_connection = tcp_device.create_connection();
        let unix_device = KmsProcess::create_unix(key_type);
        let unix_connection = unix_device.create_connection();

        Self {
            tcp_device,
            tcp_connection,
            unix_device,
            unix_connection,
        }
    }

    /// Run `test` against a TCP and a UNIX KMS, then check that neither logged anything:
    /// passing tests must print nothing, so a healthy KMS must log nothing
    pub fn apply<F>(key_type: &KeyType, test: F)
    where
        F: FnOnce(&mut ProtocolTester),
    {
        let mut pt = Self::start(key_type);
        test(&mut pt);

        for kms in [&mut pt.tcp_device, &mut pt.unix_device] {
            assert_eq!(kms.stop(), "", "a healthy KMS logged something");
        }
    }
}

impl Drop for ProtocolTester {
    fn drop(&mut self) {
        match fs::remove_file("test_chain_id_priv_validator_state.json") {
            Err(ref e) if e.kind() != io::ErrorKind::NotFound => {
                panic!("{}", e);
            }
            _ => (),
        }
    }
}

impl Connection for ProtocolTester {}

impl ReadMsg<proto::privval::Message> for ProtocolTester {
    fn read_msg(&mut self) -> p2p::Result<proto::privval::Message> {
        let tcp_msg = self.tcp_connection.read_msg()?;
        let unix_msg = self.unix_connection.read_msg()?;
        assert_eq!(tcp_msg, unix_msg);
        Ok(tcp_msg)
    }
}

impl WriteMsg<proto::privval::Message> for ProtocolTester {
    fn write_msg(&mut self, msg: &proto::privval::Message) -> p2p::Result<()> {
        self.tcp_connection.write_msg(msg)?;
        self.unix_connection.write_msg(msg)?;
        Ok(())
    }
}

/// Get the Ed25519 signing keypair used by the tests
fn test_ed25519_signing_keypair() -> ed25519::SigningKey {
    tmkms::key_utils::load_signing_key(signing_key_path(&KeyType::Consensus)).unwrap()
}

/// Get the Ed25519 identity keypair used by the tests
fn test_ed25519_identity_keypair() -> ed25519_dalek::SigningKey {
    tmkms::key_utils::load_identity_key(signing_key_path(&KeyType::Consensus)).unwrap()
}

/// Get the Secp256k1 signing keypair used by the tests
fn test_secp256k1_keypair() -> (k256::ecdsa::SigningKey, k256::ecdsa::VerifyingKey) {
    tmkms::key_utils::load_base64_secp256k1_key(signing_key_path(&KeyType::Account)).unwrap()
}

fn signing_key_path(key_type: &KeyType) -> &'static str {
    match key_type {
        KeyType::Account => SIGNING_SECP256K1_KEY_PATH,
        KeyType::Consensus => SIGNING_ED25519_KEY_PATH,
    }
}

/// Create the state file a fresh KMS would, with the KMS's own code, so that it loads
/// the file instead of warning that double-sign protection has no history
fn seeded_state_file(dir: &TempDir) -> String {
    let path = dir.path().join("state.json");
    tmkms::chain::State::load_state(&path).unwrap();
    path.display().to_string()
}

/// Copy a key fixture into `dir` as a file only its owner can read, the way a real
/// deployment keeps it, and return the copy's path
fn owner_only_copy(fixture: &str, dir: &TempDir) -> String {
    let path = dir.path().join(Path::new(fixture).file_name().unwrap());
    fs::copy(fixture, &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path.display().to_string()
}

/// A KMS that dies before connecting fails its test with the KMS's own error, rather
/// than leaving the test waiting for a connection that never comes
#[test]
#[should_panic(expected = "couldn't read key from")]
fn a_kms_that_dies_before_connecting_fails_its_test_with_its_log() {
    KmsProcess::create_unix_with(&KeyType::Consensus, |kms_dir| {
        fs::remove_file(kms_dir.join("signing_ed25519.key")).unwrap();
    });
}

/// The harness keeps two warnings out of every other test, so this one checks that a
/// KMS still gives them: about a key file others can read, and about a state file it
/// had to create
#[test]
fn kms_warns_about_a_readable_key_and_a_missing_state_file() {
    let mut kms = KmsProcess::create_unix_with(&KeyType::Consensus, |kms_dir| {
        let key = kms_dir.join("signing_ed25519.key");
        fs::set_permissions(key, fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(kms_dir.join("state.json")).unwrap();
    });
    let key = kms.kms_dir.path().join("signing_ed25519.key");
    let state = kms.kms_dir.path().join("state.json");
    let log = kms.stop();

    assert!(
        log.contains(&format!(
            "{} is readable by users other than its owner (mode 0644): \
             restrict it with `chmod 600`",
            key.display()
        )),
        "{log}"
    );
    assert!(
        log.contains(&format!(
            "[test_chain_id] no state file found: created {} at height 0, \
             so double signing protection has no history",
            state.display()
        )),
        "{log}"
    );
}

/// A KMS that finds no state file warns that double-sign protection has no history,
/// so every config the harness writes must point at a state file that already exists
#[test]
fn generated_configs_point_at_an_existing_state_file() {
    for key_type in [KeyType::Account, KeyType::Consensus] {
        let (tcp_dir, unix_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let configs = [
            KmsProcess::create_tcp_config(60000, &key_type, &tcp_dir),
            KmsProcess::create_unix_config("/tmp/tmkms-unused.sock", &key_type, &unix_dir),
        ];

        for config in configs {
            let config: toml::Table =
                toml::from_str(&fs::read_to_string(config.path()).unwrap()).unwrap();

            for chain in config["chain"].as_array().unwrap() {
                let path = chain["state_file"].as_str().unwrap();
                assert!(Path::new(path).exists(), "{path} does not exist yet");
            }
        }
    }
}

/// The KMS warns about any key file others can read, and git stores the committed
/// fixtures as 0644, so every config the harness writes must point at owner-only
/// copies instead
#[test]
fn generated_configs_point_at_owner_only_key_files() {
    let dir = tempfile::tempdir().unwrap();

    for key_type in [KeyType::Account, KeyType::Consensus] {
        let configs = [
            KmsProcess::create_tcp_config(60000, &key_type, &dir),
            KmsProcess::create_unix_config("/tmp/tmkms-unused.sock", &key_type, &dir),
        ];

        for config in configs {
            let config: toml::Table =
                toml::from_str(&fs::read_to_string(config.path()).unwrap()).unwrap();
            let secret_keys = config["validator"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|validator| validator.get("secret_key"));
            let signing_keys = config["providers"]["softsign"]
                .as_array()
                .unwrap()
                .iter()
                .map(|provider| &provider["path"]);

            for path in secret_keys.chain(signing_keys) {
                let path = path.as_str().unwrap();
                let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
                assert_eq!(
                    mode & 0o077,
                    0,
                    "{path} is readable by others (mode {mode:04o})"
                );
            }
        }
    }
}

/// Extract the actual length of an amino message
pub fn extract_actual_len(buf: &[u8]) -> Result<u64, prost::DecodeError> {
    let mut buff = Cursor::new(buf);
    let actual_len = prost::encoding::decode_varint(&mut buff)?;
    if actual_len == 0 {
        return Ok(1);
    }
    Ok(actual_len + (prost::encoding::encoded_len_varint(actual_len) as u64))
}

#[test]
fn test_handle_and_sign_proposal_account() {
    handle_and_sign_proposal(KeyType::Account)
}

#[test]
fn test_handle_and_sign_proposal_consensus() {
    handle_and_sign_proposal(KeyType::Consensus)
}

fn handle_and_sign_proposal(key_type: KeyType) {
    let chain_id = "test_chain_id";

    let dt = "2018-02-11T07:09:22.765Z".parse::<DateTime<Utc>>().unwrap();
    let t = proto::google::protobuf::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    };

    ProtocolTester::apply(&key_type, |pt| {
        let proposal = proto::types::v1beta1::Proposal {
            r#type: ConsensusMsgType::Proposal.into(),
            height: 12345,
            round: 1,
            timestamp: Some(t),
            pol_round: -1,
            block_id: None,
            signature: vec![],
        };

        let signable_msg = ConsensusMsg::try_from(proposal.clone()).unwrap();

        let request = proto::privval::v1beta1::SignProposalRequest {
            proposal: Some(proposal),
            chain_id: chain_id.into(),
        };

        send_request(
            proto::privval::message::Sum::SignProposalRequest(request),
            pt,
        );

        let response = match read_response(pt) {
            proto::privval::message::Sum::SignedProposalResponse(resp) => resp,
            other => panic!("unexpected message type in response: {other:?}"),
        };

        let signable_bytes = signable_msg
            .canonical_bytes(chain_id.parse().unwrap())
            .unwrap();

        let prop = response
            .proposal
            .expect("proposal should be embedded but none was found");

        let r = match key_type {
            KeyType::Account => {
                let signature =
                    k256::ecdsa::Signature::try_from(prop.signature.as_slice()).unwrap();
                test_secp256k1_keypair()
                    .1
                    .verify(&signable_bytes, &signature)
            }
            KeyType::Consensus => {
                let signature = ed25519::Signature::try_from(prop.signature.as_slice()).unwrap();
                test_ed25519_signing_keypair()
                    .verifying_key()
                    .verify(&signable_bytes, &signature)
            }
        };
        assert!(r.is_ok());
    });
}

#[test]
fn test_handle_and_sign_vote_account() {
    handle_and_sign_vote(KeyType::Account)
}

#[test]
fn test_handle_and_sign_vote_consensus() {
    handle_and_sign_vote(KeyType::Consensus)
}

fn handle_and_sign_vote(key_type: KeyType) {
    let chain_id = "test_chain_id";

    let dt = "2018-02-11T07:09:22.765Z".parse::<DateTime<Utc>>().unwrap();
    let t = proto::google::protobuf::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    };

    ProtocolTester::apply(&key_type, |pt| {
        let vote_msg = proto::types::v1beta1::Vote {
            r#type: 0x01,
            height: 12345,
            round: 2,
            timestamp: Some(t),
            block_id: Some(proto::types::v1beta1::BlockId {
                hash: b"some hash00000000000000000000000".to_vec(),
                part_set_header: Some(proto::types::v1beta1::PartSetHeader {
                    total: 1000000,
                    hash: b"parts_hash0000000000000000000000".to_vec(),
                }),
            }),
            validator_address: vec![
                0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4,
                0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35,
            ],
            validator_index: 56789,
            signature: vec![],
            // extension: vec![],
            // extension_signature: vec![],
        };

        let signable_msg = ConsensusMsg::try_from(vote_msg.clone()).unwrap();

        let vote = proto::privval::v1beta1::SignVoteRequest {
            vote: Some(vote_msg),
            chain_id: chain_id.into(),
            // skip_extension_signing: false,
        };

        send_request(proto::privval::message::Sum::SignVoteRequest(vote), pt);

        let request = match read_response(pt) {
            proto::privval::message::Sum::SignedVoteResponse(resp) => resp,
            other => panic!("unexpected message type in response: {other:?}"),
        };

        let signable_bytes = signable_msg
            .canonical_bytes(chain_id.parse().unwrap())
            .unwrap();

        let vote_msg: proto::types::v1beta1::Vote = request
            .vote
            .expect("vote should be embedded int the response but none was found");

        let sig: Vec<u8> = vote_msg.signature;
        assert_ne!(sig.len(), 0);

        let r = match key_type {
            KeyType::Account => {
                let signature = k256::ecdsa::Signature::try_from(sig.as_slice()).unwrap();
                test_secp256k1_keypair()
                    .1
                    .verify(&signable_bytes, &signature)
            }
            KeyType::Consensus => {
                let signature = ed25519::Signature::try_from(sig.as_slice()).unwrap();
                test_ed25519_signing_keypair()
                    .verifying_key()
                    .verify(&signable_bytes, &signature)
            }
        };
        assert!(r.is_ok());
    });
}

#[test]
fn test_exceed_max_height_account() {
    exceed_max_height(KeyType::Account)
}

#[test]
fn test_exceed_max_height_consensus() {
    exceed_max_height(KeyType::Consensus)
}

/// Asked to sign above its `max_height`, the KMS drops the connection without answering
/// and exits with an error naming the stop height
fn exceed_max_height(key_type: KeyType) {
    let chain_id = "test_chain_id";

    let dt = "2018-02-11T07:09:22.765Z".parse::<DateTime<Utc>>().unwrap();
    let t = proto::google::protobuf::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    };

    // Not `apply`: each KMS logs the error it is made to hit
    let mut pt = ProtocolTester::start(&key_type);

    let vote_msg = proto::types::v1beta1::Vote {
        r#type: 0x01,
        height: 500001,
        round: 2,
        timestamp: Some(t),
        block_id: Some(proto::types::v1beta1::BlockId {
            hash: b"some hash00000000000000000000000".to_vec(),
            part_set_header: Some(proto::types::v1beta1::PartSetHeader {
                total: 1000000,
                hash: b"parts_hash0000000000000000000000".to_vec(),
            }),
        }),
        validator_address: vec![
            0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4,
            0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35,
        ],
        validator_index: 56789,
        signature: vec![],
        // extension: vec![],
        // extension_signature: vec![],
    };

    let vote = proto::privval::v1beta1::SignVoteRequest {
        vote: Some(vote_msg),
        chain_id: chain_id.into(),
        // skip_extension_signing: false,
    };

    send_request(proto::privval::message::Sum::SignVoteRequest(vote), &mut pt);

    for (connection, kms) in [
        (&mut pt.tcp_connection, &mut pt.tcp_device),
        (&mut pt.unix_connection, &mut pt.unix_device),
    ] {
        let response = connection.read_msg();
        assert!(response.is_err(), "KMS answered: {response:?}");

        assert_eq!(kms.wait_for_exit().code(), Some(1));
        assert!(kms.log().contains(
            "requested signature above stop height: \
             attempted to sign at height 500001 which is greater than 500000"
        ));
    }
}

#[test]
fn test_handle_and_sign_get_publickey_account() {
    handle_and_sign_get_publickey(KeyType::Account)
}

#[test]
fn test_handle_and_sign_get_publickey_consensus() {
    handle_and_sign_get_publickey(KeyType::Consensus)
}

fn handle_and_sign_get_publickey(key_type: KeyType) {
    let chain_id = "test_chain_id";

    ProtocolTester::apply(&key_type, |pt| {
        let request = proto::privval::v1beta1::PubKeyRequest {
            chain_id: chain_id.into(),
        };

        send_request(proto::privval::message::Sum::PubKeyRequest(request), pt);

        let response = match read_response(pt) {
            proto::privval::message::Sum::PubKeyResponse(resp) => resp,
            other => panic!("unexpected message type in response: {other:?}"),
        };

        let pub_key = response
            .pub_key
            .and_then(|pk| pk.sum)
            .expect("missing public key");

        let pk_bytes = match pub_key {
            proto::crypto::v1::public_key::Sum::Ed25519(bytes) => bytes,
            proto::crypto::v1::public_key::Sum::Secp256k1(bytes) => bytes,
            other => panic!("unexpected public key type in response: {other:?}"),
        };

        assert_ne!(pk_bytes.len(), 0);
    });
}

#[test]
fn test_handle_and_sign_ping_pong() {
    let key_type = KeyType::Consensus;

    ProtocolTester::apply(&key_type, |pt| {
        let request = proto::privval::v1beta1::PingRequest {};
        send_request(proto::privval::message::Sum::PingRequest(request), pt);
        read_response(pt);
    });
}

/// Encode request as a Protobuf message
fn send_request(request: proto::privval::message::Sum, pt: &mut ProtocolTester) {
    let request = proto::privval::Message { sum: Some(request) };
    pt.write_msg(&request).unwrap();
}

/// Read the response as a Protobuf message
fn read_response(pt: &mut ProtocolTester) -> proto::privval::message::Sum {
    pt.read_msg().unwrap().sum.expect("no sum field in message")
}
