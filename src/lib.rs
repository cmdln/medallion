#![crate_name = "medallion"]
#![crate_type = "lib"]
#![doc(html_root_url = "https://commandline.github.io/medallion/")]
extern crate base64;
extern crate openssl;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use serde::{Serialize, Deserialize};
pub use error::Error;
pub use header::Header;
pub use header::Algorithm;
pub use payload::{Payload, DefaultPayload};

pub mod error;
mod header;
mod payload;
mod crypt;

pub type Result<T> = std::result::Result<T, Error>;

/// A convenient type that bins the same type parameter for the custom claims, an empty tuple, as
/// DefaultPayload so that the two aliases may be used together to reduce boilerplate when not
/// custom claims are needed.
pub type DefaultToken<H> = Token<H, ()>;

/// Main struct representing a JSON Web Token, composed of a header and a set of claims.
#[derive(Debug, Default)]
pub struct Token<H, C>
    where H: Serialize + Deserialize + PartialEq,
          C: Serialize + Deserialize + PartialEq
{
    raw: Option<String>,
    pub header: Header<H>,
    pub payload: Payload<C>,
}

/// Provide the ability to parse a token, verify it and sign/serialize it.
impl<H, C> Token<H, C>
    where H: Serialize + Deserialize + PartialEq,
          C: Serialize + Deserialize + PartialEq
{
    pub fn new(header: Header<H>, payload: Payload<C>) -> Token<H, C> {
        Token {
            raw: None,
            header: header,
            payload: payload,
        }
    }

    /// Parse a token from a string.
    pub fn parse(raw: &str) -> Result<Token<H, C>> {
        let pieces: Vec<_> = raw.split('.').collect();

        Ok(Token {
            raw: Some(raw.into()),
            header: Header::from_base64(pieces[0])?,
            payload: Payload::from_base64(pieces[1])?,
        })
    }

    /// Verify a token with a key and the token's specific algorithm.
    pub fn verify(&self, key: &[u8]) -> Result<bool> {
        let raw = match self.raw {
            Some(ref s) => s,
            None => return Ok(false),
        };

        let pieces: Vec<_> = raw.rsplitn(2, '.').collect();
        let sig = pieces[0];
        let data = pieces[1];

        Ok(crypt::verify(sig, data, key, &self.header.alg)?)
    }

    /// Generate the signed token from a key with the specific algorithm as a url-safe, base64
    /// string.
    pub fn sign(&self, key: &[u8]) -> Result<String> {
        let header = self.header.to_base64()?;
        let payload = self.payload.to_base64()?;
        let data = format!("{}.{}", header, payload);

        let sig = crypt::sign(&*data, key, &self.header.alg)?;
        Ok(format!("{}.{}", data, sig))
    }
}

impl<H, C> PartialEq for Token<H, C>
    where H: Serialize + Deserialize + PartialEq,
          C: Serialize + Deserialize + PartialEq
{
    fn eq(&self, other: &Token<H, C>) -> bool {
        self.header == other.header && self.payload == other.payload
    }
}

#[cfg(test)]
mod tests {
    use {DefaultToken, Header};
    use crypt::tests::load_pem;
    use super::Algorithm::{HS256, RS512};

    #[test]
    pub fn raw_data() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.\
                   TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let token = DefaultToken::<()>::parse(raw).unwrap();

        {
            assert_eq!(token.header.alg, HS256);
        }
        assert!(token.verify("secret".as_bytes()).unwrap());
    }

    #[test]
    pub fn roundtrip_hmac() {
        let token: DefaultToken<()> = Default::default();
        let key = "secret".as_bytes();
        let raw = token.sign(key).unwrap();
        let same = DefaultToken::parse(&*raw).unwrap();

        assert_eq!(token, same);
        assert!(same.verify(key).unwrap());
    }

    #[test]
    pub fn roundtrip_rsa() {
        let header: Header<()> = Header { alg: RS512, ..Default::default() };
        let token = DefaultToken { header: header, ..Default::default() };
        let private_key = load_pem("./examples/privateKey.pem").unwrap();
        let raw = token.sign(private_key.as_bytes()).unwrap();
        let same = DefaultToken::parse(&*raw).unwrap();

        assert_eq!(token, same);
        let public_key = load_pem("./examples/publicKey.pub").unwrap();
        assert!(same.verify(public_key.as_bytes()).unwrap());
    }
}
