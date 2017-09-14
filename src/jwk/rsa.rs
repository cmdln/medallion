use base64::{encode_config, decode_config, URL_SAFE_NO_PAD};
use openssl::bn::{BigNum, BigNumRef};
use openssl::rsa::Rsa;

use {error, Result};

/// Parameters included in an RSA private key.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RsaParams {
    pub n: String,
    pub e: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
}

/// Convenience methods for consuming and producing usable RSA objects from the parameters.
impl RsaParams {
    pub fn from_public_key_pem(pem: &[u8]) -> Result<RsaParams> {
        let key_pair = Rsa::public_key_from_pem(pem)?;
        Self::from_rsa(key_pair)
    }

    pub fn from_private_key_pem(pem: &[u8]) -> Result<RsaParams> {
        let key_pair = Rsa::private_key_from_pem(pem)?;
        Self::from_rsa(key_pair)
    }

    pub fn from_rsa(rsa: Rsa) -> Result<RsaParams> {
        if let (Some(n), Some(e)) = (rsa.n(), rsa.e()) {
            if let (Some(d), Some(p), Some(q)) = (rsa.d(), rsa.p(), rsa.q()) {
                let one = BigNum::from_u32(1).unwrap();
                let dp = d % &(p - &one);
                let dq = q % &(q - &one);
                let qi = &(q - &one) % p;
                Ok(RsaParams {
                    n: encode_param(n),
                    e: encode_param(e),
                    d: Some(encode_param(d)),
                    p: Some(encode_param(p)),
                    q: Some(encode_param(q)),
                    dp: Some(encode_param(&dp)),
                    dq: Some(encode_param(&dq)),
                    qi: Some(encode_param(&qi)),
                })
            } else {
                Ok(RsaParams {
                    n: encode_param(n),
                    e: encode_param(e),
                    ..Default::default()
                })
            }
        } else {
            return Err(error::Error::Custom(String::from("Missing n or e parameter of public \
                                                          key!")));
        }
    }

    pub fn to_public_key_pem(&self) -> Result<Vec<u8>> {
        let key_pair = self.to_rsa()?;
        Ok(key_pair.public_key_to_pem()?)
    }

    pub fn to_private_key_pem(&self) -> Result<Vec<u8>> {
        let key_pair = self.to_rsa()?;
        Ok(key_pair.private_key_to_pem()?)
    }

    pub fn to_rsa(&self) -> Result<Rsa> {
        if self.is_private_key() {
            Ok(Rsa::from_private_components(recover_param(&self.n)?,
                                            recover_param(&self.e)?,
                                            recover_optional_param(&self.d)?,
                                            recover_optional_param(&self.p)?,
                                            recover_optional_param(&self.q)?,
                                            recover_optional_param(&self.dp)?,
                                            recover_optional_param(&self.dq)?,
                                            recover_optional_param(&self.qi)?)?)
        } else {
            Ok(Rsa::from_public_components(recover_param(&self.n)?, recover_param(&self.e)?)?)
        }
    }

    pub fn is_private_key(&self) -> bool {
        [&self.d, &self.p, &self.q, &self.dp, &self.dq, &self.qi]
            .iter()
            .all(|param| param.is_some())
    }
}

fn recover_optional_param(param: &Option<String>) -> Result<BigNum> {
    if let Some(ref param) = *param {
        Ok(BigNum::from_slice(&decode_config(param, URL_SAFE_NO_PAD)?)?)
    } else {
        return Err(error::Error::Custom(String::from("Missing parameter!")));
    }
}

fn recover_param(param: &str) -> Result<BigNum> {
    Ok(BigNum::from_slice(&decode_config(param, URL_SAFE_NO_PAD)?)?)
}

fn encode_param(param: &BigNumRef) -> String {
    encode_config(&param.to_vec(), URL_SAFE_NO_PAD)
}

#[cfg(test)]
mod tests {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::{Signer, Verifier};
    use super::RsaParams;

    #[test]
    pub fn priv_params() {
        let rsa_keypair = Rsa::generate(2048).unwrap();
        let priv_params =
            RsaParams::from_private_key_pem(&rsa_keypair.private_key_to_pem().unwrap()).unwrap();
        assert!(priv_params.is_private_key());
        let recovered = priv_params.to_rsa().unwrap();
        assert_eq!(rsa_keypair.n().unwrap(), recovered.n().unwrap());
        assert_eq!(rsa_keypair.e().unwrap(), recovered.e().unwrap());
        assert_eq!(rsa_keypair.d().unwrap(), recovered.d().unwrap());
        assert_eq!(rsa_keypair.p().unwrap(), recovered.p().unwrap());
        assert_eq!(rsa_keypair.q().unwrap(), recovered.q().unwrap());
    }

    #[test]
    pub fn sign_verify() {
        let data = b"Hello";
        let data2 = b"Good bye";
        let rsa_keypair = Rsa::generate(2048).unwrap();
        let pub_params = RsaParams::from_public_key_pem(&rsa_keypair.public_key_to_pem().unwrap())
            .unwrap();
        let pkey = PKey::from_rsa(rsa_keypair).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.update(data).unwrap();
        signer.update(data2).unwrap();
        let signature = signer.finish().unwrap();

        let recovered = pub_params.to_rsa().unwrap();
        let keypair = PKey::from_rsa(recovered).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
        verifier.update(data).unwrap();
        verifier.update(data2).unwrap();
        assert!(verifier.finish(&signature).unwrap());
    }
}
