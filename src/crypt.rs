use base64::{decode_config, encode_config, URL_SAFE};
use header::Algorithm;
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

pub fn sign(data: &str, key: &[u8], algorithm: &Algorithm) -> String {
    match algorithm {
        &Algorithm::HS256 => sign_hmac(data, key, MessageDigest::sha256()),
        &Algorithm::HS384 => sign_hmac(data, key, MessageDigest::sha384()),
        &Algorithm::HS512 => sign_hmac(data, key, MessageDigest::sha512()),
        &Algorithm::RS256 => sign_rsa(data, key, MessageDigest::sha256()),
        &Algorithm::RS384 => sign_rsa(data, key, MessageDigest::sha384()),
        &Algorithm::RS512 => sign_rsa(data, key, MessageDigest::sha512()),
    }
}

pub fn verify(target: &str, data: &str, key: &[u8], algorithm: &Algorithm) -> bool {
    match algorithm {
        &Algorithm::HS256 => verify_hmac(target, data, key, MessageDigest::sha256()),
        &Algorithm::HS384 => verify_hmac(target, data, key, MessageDigest::sha384()),
        &Algorithm::HS512 => verify_hmac(target, data, key, MessageDigest::sha512()),
        &Algorithm::RS256 => verify_rsa(target, data, key, MessageDigest::sha256()),
        &Algorithm::RS384 => verify_rsa(target, data, key, MessageDigest::sha384()),
        &Algorithm::RS512 => verify_rsa(target, data, key, MessageDigest::sha512()),
    }
}

pub fn sign_hmac(data: &str, key: &[u8], digest: MessageDigest) -> String {
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

pub fn verify_hmac(target: &str, data: &str, key: &[u8], digest: MessageDigest) -> bool {
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

#[cfg(test)]
mod tests {
    use header::Algorithm;
    use std::io::{Error, Read};
    use std::fs::File;
    use super::{sign, verify};

    #[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
    struct EmptyClaim { }

    #[test]
    pub fn sign_data_hmac() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let real_sig = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ=";
        let data = format!("{}.{}", header, claims);

        let sig = sign(&*data, "secret".as_bytes(), &Algorithm::HS256);

        assert_eq!(sig, real_sig);
    }

    #[test]
    pub fn sign_data_rsa() {
        let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let real_sig = "nXdpIkFQYZXZ0VlJjHmAc5_aewHCCJpT5jP1fpexUCF_9m3NxlC7uYNXAl6NKno520oh9wVT4VV_vmPeEin7BnnoIJNPcImWcUzkYpLTrDBntiF9HCuqFaniuEVzlf8dVlRJgo8QxhmUZEjyDFjPZXZxPlPV1LD6hrtItxMKZbh1qoNY3OL7Mwo-WuSRQ0mmKj-_y3weAmx_9EaTLY639uD8-o5iZxIIf85U4e55Wdp-C9FJ4RxyHpjgoG8p87IbChfleSdWcZL3NZuxjRCHVWgS1uYG0I-LqBWpWyXnJ1zk6-w4tfxOYpZFMOIyq4tY2mxJQ78Kvcu8bTO7UdI7iA==";
        let data = format!("{}.{}", header, claims);

        let key = load_key("./examples/privateKey.pem").unwrap();

        let sig = sign(&*data, key.as_bytes(), &Algorithm::RS256);

        assert_eq!(sig.trim(), real_sig);
    }

    #[test]
    pub fn verify_data_hmac() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let target = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let data = format!("{}.{}", header, claims);

        assert!(verify(target, &*data, "secret".as_bytes(), &Algorithm::HS256));
    }

    #[test]
    pub fn verify_data_rsa() {
        let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let real_sig = "nXdpIkFQYZXZ0VlJjHmAc5_aewHCCJpT5jP1fpexUCF_9m3NxlC7uYNXAl6NKno520oh9wVT4VV_vmPeEin7BnnoIJNPcImWcUzkYpLTrDBntiF9HCuqFaniuEVzlf8dVlRJgo8QxhmUZEjyDFjPZXZxPlPV1LD6hrtItxMKZbh1qoNY3OL7Mwo-WuSRQ0mmKj-_y3weAmx_9EaTLY639uD8-o5iZxIIf85U4e55Wdp-C9FJ4RxyHpjgoG8p87IbChfleSdWcZL3NZuxjRCHVWgS1uYG0I-LqBWpWyXnJ1zk6-w4tfxOYpZFMOIyq4tY2mxJQ78Kvcu8bTO7UdI7iA";
        let data = format!("{}.{}", header, claims);

        let key = load_key("./examples/publicKey.pub").unwrap();
        assert!(verify(&real_sig, &*data, key.as_bytes(), &Algorithm::RS256));
    }

    fn load_key(keypath: &str) -> Result<String, Error> {
        let mut key_file = try!(File::open(keypath));
        let mut key = String::new();
        try!(key_file.read_to_string(&mut key));
        Ok(key)
    }
}
