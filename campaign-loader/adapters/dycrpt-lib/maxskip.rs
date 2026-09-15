//! MAX_SKIP campaign: a jump of exactly DEFAULT_MAX_SKIP must work; a jump
//! larger than DEFAULT_MAX_SKIP must not derive unboundedly.
//!
//! Uses only the public encrypt/decrypt API. Lives in AROS, not in dycrpt.

use voicechat_crypto::{CryptoEngineApi, CryptoProfile, DeviceConfig, VoiceChatCryptoEngine};

/// Must match `voicechat_crypto::ratchet::DEFAULT_MAX_SKIP` at the pinned revision.
const DEFAULT_MAX_SKIP: u32 = 1000;

fn pair() -> Result<
    (
        VoiceChatCryptoEngine,
        VoiceChatCryptoEngine,
        voicechat_crypto::SessionId,
        voicechat_crypto::SessionId,
    ),
    String,
> {
    let mut alice = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"aros-alice-skip".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .map_err(|error| format!("init alice: {error:?}"))?;
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"aros-bob-skip".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .map_err(|error| format!("init bob: {error:?}"))?;
    let bundle = bob
        .generate_public_prekey_bundle(2)
        .map_err(|error| format!("bundle: {error:?}"))?;
    let (sid_a, packet) = alice
        .establish_outbound_session(&bundle, b"aros-maxskip", b"hello", b"ad")
        .map_err(|error| format!("outbound: {error:?}"))?;
    let (sid_b, first) = bob
        .process_inbound_session(&packet, b"aros-maxskip", b"ad")
        .map_err(|error| format!("inbound: {error:?}"))?;
    if first.as_slice() != b"hello" {
        return Err("handshake plaintext mismatch".into());
    }
    Ok((alice, bob, sid_a, sid_b))
}

fn last_of(alice: &mut VoiceChatCryptoEngine, sid: &voicechat_crypto::SessionId, count: u32) -> Result<voicechat_crypto::SealedMessage, String> {
    let mut last = None;
    for index in 0..count {
        let body = format!("skip-{index}").into_bytes();
        let sealed = alice
            .encrypt(sid, &body, b"ad")
            .map_err(|error| format!("encrypt {index}: {error:?}"))?;
        last = Some(sealed);
    }
    last.ok_or_else(|| "empty skip chain".into())
}

fn main() {
    let (mut alice, mut bob, sid_a, sid_b) = match pair() {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("dycrpt-maxskip: {error}");
            std::process::exit(2);
        }
    };
    let bounded = match last_of(&mut alice, &sid_a, DEFAULT_MAX_SKIP) {
        Ok(sealed) => sealed,
        Err(error) => {
            eprintln!("dycrpt-maxskip: bounded chain: {error}");
            std::process::exit(2);
        }
    };
    match bob.decrypt(&sid_b, &bounded, b"ad") {
        Ok(_) => println!("BOUNDED_OK"),
        Err(error) => {
            eprintln!("dycrpt-maxskip: in-bound skip failed: {error}");
            std::process::exit(2);
        }
    }

    let (mut alice2, mut bob2, sid_a2, sid_b2) = match pair() {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("dycrpt-maxskip: second pair: {error}");
            std::process::exit(2);
        }
    };
    let unbounded = match last_of(&mut alice2, &sid_a2, DEFAULT_MAX_SKIP + 2) {
        Ok(sealed) => sealed,
        Err(error) => {
            eprintln!("dycrpt-maxskip: unbounded chain: {error}");
            std::process::exit(2);
        }
    };
    match bob2.decrypt(&sid_b2, &unbounded, b"ad") {
        Ok(_) => println!("UNBOUNDED_DERIVATION"),
        Err(_) => {}
    }
}
