//! A Base64 key must not leave its decoded bytes in freed memory, even when it fails
//! to decode partway, nor a typed mnemonic its words. This is its own test binary
//! because checking that needs a global allocator that inspects every buffer as it is
//! freed.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs, slice,
    sync::atomic::{AtomicBool, Ordering},
};
use subtle_encoding::base64;
use tmkms::key_utils;

/// The secret the test keys hold. No other buffer in this process holds these bytes.
const SEED: [u8; 32] = [
    0x5e, 0xed, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
    0xdc, 0xfe, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
];

/// Part of `SEED` that decoding keeps even when it fails on the first character
fn seed_middle() -> &'static [u8] {
    &SEED[8..24]
}

/// Set when a freed buffer still held `seed_middle()`
static FREED_SEED: AtomicBool = AtomicBool::new(false);

/// An admin mnemonic as an operator types it into `yubihsm setup --restore`
#[cfg(feature = "yubihsm")]
const TYPED_MNEMONIC: &str = "abandon amount liar amount expire adjust cage candy arch gather \
                              drum bullet absurd math era live bid rhythm alien crouch range \
                              attend journey unaware\n";

/// Words of `TYPED_MNEMONIC` that no other buffer in this process holds
const MNEMONIC_WORDS: &[u8] = b"liar amount expire adjust cage candy";

/// Set when a freed buffer still held `MNEMONIC_WORDS`
static FREED_MNEMONIC: AtomicBool = AtomicBool::new(false);

/// The system allocator, recording whether a freed buffer still held a secret
struct SeedScanner;

unsafe impl GlobalAlloc for SeedScanner {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let freed = unsafe { slice::from_raw_parts(ptr, layout.size()) };
        if freed
            .windows(seed_middle().len())
            .any(|w| w == seed_middle())
        {
            FREED_SEED.store(true, Ordering::SeqCst);
        }
        if freed
            .windows(MNEMONIC_WORDS.len())
            .any(|w| w == MNEMONIC_WORDS)
        {
            FREED_MNEMONIC.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: SeedScanner = SeedScanner;

/// One test, because the allocator's record is shared by everything in this process.
/// It covers both readers of a Base64 key, key load and `yubihsm keys import`, and the
/// mnemonic reader of `yubihsm setup`.
#[test]
fn a_base64_key_leaves_no_decoded_bytes_in_freed_memory() {
    let dir = tempfile::tempdir().unwrap();
    let encoded = String::from_utf8(base64::encode(SEED)).unwrap();
    // A base64url character where standard Base64 is expected, as in a key file
    // written with the wrong alphabet
    let misencoded = format!("-{}", &encoded[1..]);

    let key = dir.path().join("key");
    fs::write(&key, &encoded).unwrap();
    drop(key_utils::load_base64_secret(&key).unwrap());
    assert!(
        !FREED_SEED.load(Ordering::SeqCst),
        "a key that decodes left its bytes in freed memory"
    );

    let misencoded_key = dir.path().join("misencoded_key");
    fs::write(&misencoded_key, &misencoded).unwrap();
    assert!(key_utils::load_base64_secret(&misencoded_key).is_err());
    assert!(
        !FREED_SEED.load(Ordering::SeqCst),
        "a key that fails to decode left its bytes in freed memory"
    );

    #[cfg(feature = "yubihsm-mock")]
    {
        use tmkms::commands::yubihsm::keys::import::ImportCommand;
        use yubihsm::{Client, Connector, Credentials};

        // The key fails to decode before the HSM is reached, so its password is moot
        let hsm = Client::create(
            Connector::mockhsm(),
            Credentials::from_password(1, b"wrong"),
        )
        .unwrap();
        let import = ImportCommand {
            key_id: Some(1),
            key_type: Some("base64".to_owned()),
            path: misencoded_key,
            ..Default::default()
        };

        assert_eq!(
            import.import(&hsm),
            Err("can't decode Ed25519 key: bad encoding".to_owned())
        );
        assert!(
            !FREED_SEED.load(Ordering::SeqCst),
            "yubihsm keys import left a key that fails to decode in freed memory"
        );
    }

    #[cfg(feature = "yubihsm")]
    {
        use tmkms::commands::yubihsm::setup::read_mnemonic;

        drop(read_mnemonic(&mut TYPED_MNEMONIC.as_bytes(), "").unwrap());
        assert!(
            !FREED_MNEMONIC.load(Ordering::SeqCst),
            "yubihsm setup left a typed mnemonic in freed memory"
        );
    }
}
