#![crate_name = "medallion"]
#![crate_type = "lib"]
#![doc(html_root_url = "https://commandline.github.io/medallion/")]
extern crate base64;
extern crate openssl;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use base64::{decode_config, encode_config, URL_SAFE};
use serde::{Serialize, Deserialize};
pub use error::Error;
pub use header::DefaultHeader;
pub use header::Algorithm;
pub use claims::Claims;
pub use claims::Registered;

pub mod error;
pub mod header;
pub mod claims;
mod crypt;

pub type Result<T> = std::result::Result<T, Error>;

/// Main struct representing a JSON Web Token, composed of a header and a set of claims.
#[derive(Debug, Default)]
pub struct Token<H, C>
    where H: Component, C: Component {
    raw: Option<String>,
    pub header: H,
    pub claims: C,
}

/// Any header type must implement this trait so that signing and verification work.
pub trait Header {
    fn alg(&self) -> &header::Algorithm;
}

/// Any header or claims type must implement this trait in order to serialize and deserialize
/// correctly.
pub trait Component: Sized {
    fn from_base64(raw: &str) -> Result<Self>;
    fn to_base64(&self) -> Result<String>;
}

/// Provide a default implementation that should work in almost all cases.
impl<T> Component for T
    where T: Serialize + Deserialize + Sized {

    /// Parse from a string.
    fn from_base64(raw: &str) -> Result<T> {
        let data = decode_config(raw, URL_SAFE)?;
        let s = String::from_utf8(data)?;
        Ok(serde_json::from_str(&*s)?)
    }

    /// Encode to a string.
    fn to_base64(&self) -> Result<String> {
        let s = serde_json::to_string(&self)?;
        let enc = encode_config((&*s).as_bytes(), URL_SAFE);
        Ok(enc)
    }
}

/// Provide the ability to parse a token, verify it and sign/serialize it.
impl<H, C> Token<H, C>
    where H: Component + Header, C: Component {
    pub fn new(header: H, claims: C) -> Token<H, C> {
        Token {
            raw: None,
            header: header,
            claims: claims,
        }
    }

    /// Parse a token from a string.
    pub fn parse(raw: &str) -> Result<Token<H, C>> {
        let pieces: Vec<_> = raw.split('.').collect();

        Ok(Token {
            raw: Some(raw.into()),
            header: Component::from_base64(pieces[0])?,
            claims: Component::from_base64(pieces[1])?,
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

        Ok(crypt::verify(sig, data, key, &self.header.alg())?)
    }

    /// Generate the signed token from a key with the specific algorithm as a url-safe, base64
    /// string.
    pub fn signed(&self, key: &[u8]) -> Result<String> {
        let header = Component::to_base64(&self.header)?;
        let claims = self.claims.to_base64()?;
        let data = format!("{}.{}", header, claims);

        let sig = crypt::sign(&*data, key, &self.header.alg())?;
        Ok(format!("{}.{}", data, sig))
    }
}

impl<H, C> PartialEq for Token<H, C>
    where H: Component + PartialEq, C: Component + PartialEq{
    fn eq(&self, other: &Token<H, C>) -> bool {
        self.header == other.header &&
        self.claims == other.claims
    }
}

#[cfg(test)]
mod tests {
    use Claims;
    use Token;
    use header::Algorithm::{HS256,RS512};
    use header::DefaultHeader;
    use std::io::{Error, Read};
    use std::fs::File;

    #[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
    struct EmptyClaim { }

    #[test]
    pub fn raw_data() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let token = Token::<DefaultHeader, Claims<EmptyClaim>>::parse(raw).unwrap();

        {
            assert_eq!(token.header.alg, HS256);
        }
        assert!(token.verify("secret".as_bytes()).unwrap());
    }

    #[test]
    pub fn roundtrip_hmac() {
        let token: Token<DefaultHeader, Claims<EmptyClaim>> = Default::default();
        let key = "secret".as_bytes();
        let raw = token.signed(key).unwrap();
        let same = Token::parse(&*raw).unwrap();

        assert_eq!(token, same);
        assert!(same.verify(key).unwrap());
    }

    #[test]
    pub fn roundtrip_rsa() {
        let token: Token<DefaultHeader, Claims<EmptyClaim>> = Token {
            header: DefaultHeader {
                alg: RS512,
                ..Default::default()
            },
            ..Default::default()
        };
        let private_key = load_key("./examples/privateKey.pem").unwrap();
        let raw = token.signed(private_key.as_bytes()).unwrap();
        let same = Token::parse(&*raw).unwrap();

        assert_eq!(token, same);
        let public_key = load_key("./examples/publicKey.pub").unwrap();
        assert!(same.verify(public_key.as_bytes()).unwrap());
    }

    fn load_key(keypath: &str) -> Result<String, Error> {
        let mut key_file = File::open(keypath)?;
        let mut key = String::new();
        key_file.read_to_string(&mut key)?;
        Ok(key)
    }
}
