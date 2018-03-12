use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use header::Algorithm;
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use super::Result;

pub fn sign(data: &str, key: &[u8], algorithm: &Algorithm) -> Result<String> {
    match *algorithm {
        Algorithm::HS256 => sign_hmac(data, key, MessageDigest::sha256()),
        Algorithm::HS384 => sign_hmac(data, key, MessageDigest::sha384()),
        Algorithm::HS512 => sign_hmac(data, key, MessageDigest::sha512()),
        Algorithm::RS256 => sign_rsa(data, key, MessageDigest::sha256()),
        Algorithm::RS384 => sign_rsa(data, key, MessageDigest::sha384()),
        Algorithm::RS512 => sign_rsa(data, key, MessageDigest::sha512()),
    }
}

pub fn verify(target: &str, data: &str, key: &[u8], algorithm: &Algorithm) -> Result<bool> {
    match *algorithm {
        Algorithm::HS256 => verify_hmac(target, data, key, MessageDigest::sha256()),
        Algorithm::HS384 => verify_hmac(target, data, key, MessageDigest::sha384()),
        Algorithm::HS512 => verify_hmac(target, data, key, MessageDigest::sha512()),
        Algorithm::RS256 => verify_rsa(target, data, key, MessageDigest::sha256()),
        Algorithm::RS384 => verify_rsa(target, data, key, MessageDigest::sha384()),
        Algorithm::RS512 => verify_rsa(target, data, key, MessageDigest::sha512()),
    }
}

fn sign_hmac(data: &str, key: &[u8], digest: MessageDigest) -> Result<String> {
    let secret_key = PKey::hmac(key)?;

    let mut signer = Signer::new(digest, &secret_key)?;
    signer.update(data.as_bytes())?;

    let mac = signer.sign_to_vec()?;
    Ok(encode_config(&mac, URL_SAFE_NO_PAD))
}

fn sign_rsa(data: &str, key: &[u8], digest: MessageDigest) -> Result<String> {
    let private_key = Rsa::private_key_from_pem(key)?;
    let pkey = PKey::from_rsa(private_key)?;

    let mut signer = Signer::new(digest, &pkey)?;
    signer.update(data.as_bytes())?;
    let sig = signer.sign_to_vec()?;
    Ok(encode_config(&sig, URL_SAFE_NO_PAD))
}

fn verify_hmac(target: &str, data: &str, key: &[u8], digest: MessageDigest) -> Result<bool> {
    let target_bytes: Vec<u8> = decode_config(target, URL_SAFE_NO_PAD)?;
    let secret_key = PKey::hmac(key)?;

    let mut signer = Signer::new(digest, &secret_key)?;
    signer.update(data.as_bytes())?;

    let mac = signer.sign_to_vec()?;

    Ok(memcmp::eq(&mac, &target_bytes))
}

fn verify_rsa(signature: &str, data: &str, key: &[u8], digest: MessageDigest) -> Result<bool> {
    let signature_bytes: Vec<u8> = decode_config(signature, URL_SAFE_NO_PAD)?;
    let public_key = Rsa::public_key_from_pem(key)?;
    let pkey = PKey::from_rsa(public_key)?;
    let mut verifier = Verifier::new(digest, &pkey)?;
    verifier.update(data.as_bytes())?;
    Ok(verifier.verify(&signature_bytes)?)
}

#[cfg(test)]
pub mod tests {
    use header::Algorithm;
    use openssl;
    use super::{sign, verify};

    #[test]
    pub fn sign_data_hmac() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let real_sig = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let data = format!("{}.{}", header, claims);

        let sig = sign(&*data, "secret".as_bytes(), &Algorithm::HS256);

        assert_eq!(sig.unwrap(), real_sig);
    }

    #[test]
    pub fn sign_and_verify_data_rsa() {
        let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

        let data = format!("{}.{}", header, claims);

        let keypair = openssl::rsa::Rsa::generate(2048).unwrap();

        let sig = sign(
            &*data,
            &keypair.private_key_to_pem().unwrap(),
            &Algorithm::RS256,
        ).unwrap();

        assert!(
            verify(
                &sig,
                &*data,
                &keypair.public_key_to_pem().unwrap(),
                &Algorithm::RS256
            ).unwrap()
        );
    }

    #[test]
    pub fn verify_data_hmac() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let target = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let data = format!("{}.{}", header, claims);

        assert!(verify(target, &*data, "secret".as_bytes(), &Algorithm::HS256).unwrap());
    }
}
