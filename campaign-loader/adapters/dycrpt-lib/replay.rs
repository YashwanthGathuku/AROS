//! Replay campaign: first decrypt must work; second decrypt of the same
//! SealedMessage must not yield the plaintext.
//!
//! This is the receive/`open` path on VoiceChatCryptoEngine. It lives in AROS,
//! not in dycrpt.

use voicechat_crypto::{CryptoEngineApi, CryptoProfile, DeviceConfig, VoiceChatCryptoEngine};

fn main() {
    let mut alice = match VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"aros-alice".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    }) {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("dycrpt-replay: initialize alice failed: {error:?}");
            std::process::exit(2);
        }
    };
    let mut bob = match VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"aros-bob".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    }) {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("dycrpt-replay: initialize bob failed: {error:?}");
            std::process::exit(2);
        }
    };
    let bundle = match bob.generate_public_prekey_bundle(2) {
        Ok(bundle) => bundle,
        Err(error) => {
            eprintln!("dycrpt-replay: prekey bundle failed: {error:?}");
            std::process::exit(2);
        }
    };
    let (sid_a, packet) = match alice.establish_outbound_session(&bundle, b"aros-replay", b"hello", b"ad")
    {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("dycrpt-replay: outbound session failed: {error:?}");
            std::process::exit(2);
        }
    };
    let (sid_b, first) = match bob.process_inbound_session(&packet, b"aros-replay", b"ad") {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("dycrpt-replay: inbound session failed: {error:?}");
            std::process::exit(2);
        }
    };
    if first.as_slice() != b"hello" {
        eprintln!("dycrpt-replay: handshake plaintext mismatch");
        std::process::exit(2);
    }
    let sealed = match alice.encrypt(&sid_a, b"payload-1", b"ad") {
        Ok(sealed) => sealed,
        Err(error) => {
            eprintln!("dycrpt-replay: encrypt failed: {error:?}");
            std::process::exit(2);
        }
    };
    match bob.decrypt(&sid_b, &sealed, b"ad") {
        Ok(plaintext) if plaintext.as_slice() == b"payload-1" => {
            println!("OPEN_OK");
        }
        Ok(_) => {
            eprintln!("dycrpt-replay: first decrypt plaintext mismatch");
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("dycrpt-replay: first decrypt failed: {error:?}");
            std::process::exit(2);
        }
    }
    match bob.decrypt(&sid_b, &sealed, b"ad") {
        Ok(_) => println!("REPLAY_ACCEPTED"),
        Err(_) => println!("REPLAY_REJECTED"),
    }
}
