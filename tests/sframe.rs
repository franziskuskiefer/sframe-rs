use evercrypt::prelude::*;
use sframe::{
    header::{Header, Metadata},
    keys::{Key, Keystore},
    sframe::{FrameType, Sframe},
};

#[test]
fn self_enc_dec_test() {
    let sender_key = Key::new(&get_random_array::<[u8; 32]>());

    let mut sender_key_store = Keystore::new();
    sender_key_store.add_key(0, sender_key.clone());

    let mut receiver_key_store = Keystore::new();
    receiver_key_store.add_key(0, sender_key);

    let metadata = Metadata::new(false, 0);
    let mut header = Header::new(metadata, 0);

    let plaintext_frame = b"This isn't really an audio frame";

    let encrypted_frame = Sframe::encrypt(
        plaintext_frame,
        &mut header,
        &sender_key_store,
        &FrameType::Audio,
    )
    .unwrap();
    let decrypted_frame = Sframe::decrypt(
        encrypted_frame.get_payload(),
        &header,
        encrypted_frame.get_auth_tag(),
        &mut receiver_key_store,
        &FrameType::Audio,
    )
    .unwrap();

    assert_eq!(&plaintext_frame[..], &decrypted_frame[..]);
}

#[test]
fn self_enc_dec_ratchet_test() {
    let sender_key = Key::new(&get_random_array::<[u8; 32]>());

    let mut sender_key_store = Keystore::new();
    sender_key_store.add_key(0, sender_key.clone());
    // move the key forward
    sender_key_store.get_key_mut(0).unwrap().ratchet();

    let mut receiver_key_store = Keystore::new();
    receiver_key_store.add_key(0, sender_key);

    let metadata = Metadata::new(false, 0);
    let mut header = Header::new(metadata, 0);

    let plaintext_frame = b"This isn't really an audio frame";

    let encrypted_frame = Sframe::encrypt(
        plaintext_frame,
        &mut header,
        &sender_key_store,
        &FrameType::Audio,
    )
    .unwrap();
    let decrypted_frame = Sframe::decrypt(
        encrypted_frame.get_payload(),
        &header,
        encrypted_frame.get_auth_tag(),
        &mut receiver_key_store,
        &FrameType::Audio,
    )
    .unwrap();

    assert_eq!(&plaintext_frame[..], &decrypted_frame[..]);
}
