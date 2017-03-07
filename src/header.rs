use base64::{encode_config, decode_config, URL_SAFE_NO_PAD};
use serde::{Serialize, Deserialize};
use serde_json::{self, Value};
use std::default::Default;

use super::error::Error;
use super::Result;

/// A extensible Header that provides only algorithm field and allows for additional fields to be
/// passed in via a struct that can be serialized and deserialized. Unlike the Claims struct, there
/// is no convenience type alias because headers seem to vary much more greatly in practice
/// depending on the application whereas claims seem to be shared as a function of registerest and
/// public claims.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Header<T: Serialize + Deserialize> {
    pub alg: Algorithm,
    #[serde(skip_serializing)]
    pub headers: Option<T>,
}

/// Supported algorithms, each representing a valid signature and digest combination.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
}

impl<T: Serialize + Deserialize> Header<T> {
    pub fn from_base64(raw: &str) -> Result<Header<T>> {
        let data = decode_config(raw, URL_SAFE_NO_PAD)?;
        let own: Header<T> = serde_json::from_slice(&data)?;

        let headers: Option<T> = serde_json::from_slice(&data).ok();


        Ok(Header {
            alg: own.alg,
            headers: headers
        })
    }

    /// Encode to a string.
    pub fn to_base64(&self) -> Result<String> {
        if let Value::Object(mut own_map) = serde_json::to_value(&self)? {
            match self.headers {
                Some(ref headers) => {
                    if let Value::Object(extra_map) = serde_json::to_value(&headers)? {
                        own_map.extend(extra_map);
                        let s = serde_json::to_string(&own_map)?;
                        let enc = encode_config((&*s).as_bytes(), URL_SAFE_NO_PAD);
                        Ok(enc)
                    } else {
                        Err(Error::Custom("Could not access additional headers.".to_owned()))
                    }
                },
                None => {
                    let s = serde_json::to_string(&own_map)?;
                    let enc = encode_config((&*s).as_bytes(), URL_SAFE_NO_PAD);
                    Ok(enc)
                },
            }
        } else {
            Err(Error::Custom("Could not access default header.".to_owned()))
        }
    }
}

impl<T: Serialize + Deserialize> Default for Header<T> {
    fn default() -> Header<T> {
        Header {
            alg: Algorithm::HS256,
            headers: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, Header};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct CustomHeaders {
        kid: String,
        typ: String,
    }

    #[test]
    fn from_base64() {
        let enc = "eyJhbGciOiJIUzI1NiJ9";
        let header: Header<()> = Header::from_base64(enc).unwrap();

        assert_eq!(header.alg, Algorithm::HS256);
    }

    #[test]
    fn custom_from_base64() {
        let enc = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjFLU0YzZyIsInR5cCI6IkpXVCJ9";
        let header: Header<CustomHeaders> = Header::from_base64(enc).unwrap();

        let headers = header.headers.unwrap();
        assert_eq!(headers.kid, "1KSF3g".to_string());
        assert_eq!(headers.typ, "JWT".to_string());
        assert_eq!(header.alg, Algorithm::HS256);
    }

    #[test]
    fn to_base64() {
        let enc = "eyJhbGciOiJIUzI1NiJ9";
        let header: Header<()> = Default::default();

        assert_eq!(enc, header.to_base64().unwrap());
    }

    #[test]
    fn custom_to_base64() {
        let enc = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjFLU0YzZyIsInR5cCI6IkpXVCJ9";
        let header: Header<CustomHeaders> = Header {
            headers: Some(CustomHeaders {
                kid: "1KSF3g".into(),
                typ: "JWT".into(),
            }),
            ..Default::default()
        };

        assert_eq!(enc, header.to_base64().unwrap());
    }

    #[test]
    fn roundtrip() {
        let header: Header<()> = Default::default();
        let enc = header.to_base64().unwrap();
        assert_eq!(header, Header::from_base64(&*enc).unwrap());
    }

    #[test]
    fn roundtrip_custom() {
        let header: Header<CustomHeaders> = Header {
            alg: Algorithm::RS512,
            headers: Some(CustomHeaders {
                kid: "1KSF3g".into(),
                typ: "JWT".into(),
            }),
        };
        let enc = header.to_base64().unwrap();
        assert_eq!(header, Header::from_base64(&*enc).unwrap());
    }
}
