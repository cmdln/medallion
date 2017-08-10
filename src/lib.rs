#![crate_name = "medallion"]
#![crate_type = "lib"]
#![doc(html_root_url = "https://commandline.github.io/medallion/")]
///! A crate for working with JSON WebTokens that use OpenSSL for RSA signing and encryption and
///! serde and serde_json for JSON encoding and decoding.
///!
///! Tries to support the standard uses for JWTs while providing reasonable ways to extend,
///! primarily by adding custom headers and claims to tokens.
extern crate base64;
extern crate openssl;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate time;

pub use error::Error;
pub use jwt::{Token, Header, Algorithm, Payload};
use jwk::Key;
pub use jwk::{KeySet, KeyType, OctetSequenceParams, RsaPrivateParams, RsaPublicParams};

pub mod error;
mod jwk;
mod jwt;

pub type Result<T> = std::result::Result<T, Error>;

/// JWK for an RSA private key.
pub type RsaPrivateKey = Key<RsaPrivateParams>;

/// JWK for an RSA public key.
pub type RsaPublicKey = Key<RsaPublicParams>;

/// JWK for a byte sequence based key.
pub type OctetSequenceKey = Key<OctetSequenceParams>;

/// A convenient type that binds the same type parameter for the custom claims, an empty tuple, as
/// DefaultPayload so that the two aliases may be used together to reduce boilerplate when no
/// custom claims are needed.
pub type DefaultToken<H> = Token<H, ()>;

/// A convenient type alias that assumes the standard claims are sufficient, the empty tuple type
/// satisfies Claims' generic parameter as simply and clearly as possible.
pub type DefaultPayload = Payload<()>;
