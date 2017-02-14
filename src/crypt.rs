use base64::{decode_config, encode_config, URL_SAFE};
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

pub fn sign(data: &str, key: &[u8], digest: MessageDigest) -> String {
    let secret_key = PKey::hmac(key).unwrap();

    let mut signer = Signer::new(digest, &secret_key).unwrap();
    signer.update(data.as_bytes()).unwrap();

    let mac = signer.finish().unwrap();
    encode_config(&mac, URL_SAFE)
}

pub fn sign_rsa(data: &str, key: &[u8], digest: MessageDigest) -> String {
    let private_key = Rsa::private_key_from_pem(key).unwrap();
    let pkey = PKey::from_rsa(private_key).unwrap();

    let mut signer = Signer::new(digest, &pkey).unwrap();
    signer.update(data.as_bytes()).unwrap();
    let sig = signer.finish().unwrap();
    encode_config(&sig, URL_SAFE)
}

pub fn verify(target: &str, data: &str, key: &[u8], digest: MessageDigest) -> bool {
    let target_bytes: Vec<u8> = decode_config(target, URL_SAFE).unwrap();
    let secret_key = PKey::hmac(key).unwrap();

    let mut signer = Signer::new(digest, &secret_key).unwrap();
    signer.update(data.as_bytes()).unwrap();

    let mac = signer.finish().unwrap();

    memcmp::eq(&mac, &target_bytes)
}

pub fn verify_rsa(signature: &str, data: &str, key: &[u8], digest: MessageDigest) -> bool {
    let signature_bytes: Vec<u8> = decode_config(signature, URL_SAFE).unwrap();
    let public_key = Rsa::public_key_from_pem(key).unwrap();
    let pkey = PKey::from_rsa(public_key).unwrap();
    let mut verifier = Verifier::new(digest, &pkey).unwrap();
    verifier.update(data.as_bytes()).unwrap();
    verifier.finish(&signature_bytes).unwrap()
}
