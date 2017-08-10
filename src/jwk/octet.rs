use base64::{encode_config, decode_config, URL_SAFE_NO_PAD};
use error::Error;
use {Algorithm, Result};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct OctetSequenceParams {
    pub alg: Algorithm,
    pub k: Option<String>,
}

impl OctetSequenceParams {
    pub fn from_slice(algorithm: Algorithm, bytes: &[u8]) -> OctetSequenceParams {
        OctetSequenceParams {
            alg: algorithm,
            k: Some(encode_config(bytes, URL_SAFE_NO_PAD)),
        }
    }

    pub fn as_slice(&self) -> Result<Vec<u8>> {
        if let Some(ref key) = self.k.as_ref() {
            Ok(decode_config(&key, URL_SAFE_NO_PAD)?)
        } else {
            Err(Error::Custom("Key parameter is None!".to_owned()))
        }
    }
}

impl Default for OctetSequenceParams {
    fn default() -> OctetSequenceParams {
        OctetSequenceParams {
            alg: Algorithm::HS256,
            k: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use openssl::hash::MessageDigest;
    use openssl::memcmp;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use Algorithm;
    use super::OctetSequenceParams;

    #[test]
    pub fn sign_verify() {
        let data = b"Hello";
        let data2 = b"Good bye";
        let params = OctetSequenceParams::from_slice(Algorithm::HS512, b"foobley bletch");
        let pkey = PKey::hmac(&params.as_slice().unwrap()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha512(), &pkey).unwrap();
        signer.update(data).unwrap();
        signer.update(data2).unwrap();
        let target = signer.finish().unwrap();

        let recovered = OctetSequenceParams::from_slice(Algorithm::HS512,
                                                        &params.as_slice().unwrap());
        let pkey = PKey::hmac(&recovered.as_slice().unwrap()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha512(), &pkey).unwrap();
        signer.update(data).unwrap();
        signer.update(data2).unwrap();
        let signature = signer.finish().unwrap();
        assert!(memcmp::eq(&signature, &target));
    }
}
