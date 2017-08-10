use base64::{encode_config, decode_config, URL_SAFE_NO_PAD};
use openssl::bn::{BigNum, BigNumRef};
use openssl::rsa::Rsa;
use Result;

/// Parameters included in an RSA private key.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RsaPublicParams {
    pub n: String,
    pub e: String,
}

/// Convenience methods for consuming and producing usable RSA objects from the parameters.
impl RsaPublicParams {
    pub fn from_pem(pem: &[u8]) -> Result<RsaPublicParams> {
        let key_pair = Rsa::public_key_from_pem(pem)?;
        let n = key_pair.n().unwrap();
        let e = key_pair.e().unwrap();
        Ok(RsaPublicParams {
               n: encode_param(n),
               e: encode_param(e),
           })
    }

    pub fn to_pem(&self) -> Result<Vec<u8>> {
        let key_pair = Rsa::from_public_components(recover_param(&self.n)?,
                                                   recover_param(&self.e)?)?;
        Ok(key_pair.public_key_to_pem()?)
    }
}

/// Parameters included in an RSA private key.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RsaPrivateParams {
    pub n: String,
    pub e: String,
    pub d: String,
    pub p: String,
    pub q: String,
    pub dp: String,
    pub dq: String,
    pub qi: String,
}

/// Convenience methods for consuming and producing usable RSA objects from the parameters.
impl RsaPrivateParams {
    pub fn from_pem(pem: &[u8]) -> Result<RsaPrivateParams> {
        let key_pair = Rsa::private_key_from_pem(pem)?;
        let n = key_pair.n().unwrap();
        let e = key_pair.e().unwrap();
        let d = key_pair.d().unwrap();
        let p = key_pair.p().unwrap();
        let q = key_pair.q().unwrap();
        let one = BigNum::from_u32(1).unwrap();
        let dp = d % &(p - &one);
        let dq = q % &(q - &one);
        let qi = &(q - &one) % p;
        Ok(RsaPrivateParams {
               n: encode_param(n),
               e: encode_param(e),
               d: encode_param(d),
               p: encode_param(p),
               q: encode_param(q),
               dp: encode_param(&dp),
               dq: encode_param(&dq),
               qi: encode_param(&qi),
           })
    }

    pub fn to_pem(&self) -> Result<Vec<u8>> {
        let key_pair = Rsa::from_private_components(recover_param(&self.n)?,
                                                    recover_param(&self.e)?,
                                                    recover_param(&self.d)?,
                                                    recover_param(&self.p)?,
                                                    recover_param(&self.q)?,
                                                    recover_param(&self.dp)?,
                                                    recover_param(&self.dq)?,
                                                    recover_param(&self.qi)?)?;
        Ok(key_pair.private_key_to_pem()?)
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
    use super::{RsaPrivateParams, RsaPublicParams};

    #[test]
    pub fn priv_params() {
        let rsa_keypair = Rsa::generate(2048).unwrap();
        let priv_params = RsaPrivateParams::from_pem(&rsa_keypair.private_key_to_pem().unwrap())
            .unwrap();
        let recovered = Rsa::private_key_from_pem(&priv_params.to_pem().unwrap()).unwrap();
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
        let pub_params = RsaPublicParams::from_pem(&rsa_keypair.public_key_to_pem().unwrap())
            .unwrap();
        let pkey = PKey::from_rsa(rsa_keypair).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.update(data).unwrap();
        signer.update(data2).unwrap();
        let signature = signer.finish().unwrap();

        let recovered = Rsa::public_key_from_pem(&pub_params.to_pem().unwrap()).unwrap();
        let keypair = PKey::from_rsa(recovered).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
        verifier.update(data).unwrap();
        verifier.update(data2).unwrap();
        assert!(verifier.finish(&signature).unwrap());
    }
}
