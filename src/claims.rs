use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use error::Error;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::value::Value;
use super::Result;

/// A default claim set, including the standard, or registered, claims and the ability to specify
/// your own as custom claims.
#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct Claims<T: Serialize + Deserialize + PartialEq> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing)]
    pub custom: Option<T>
}

/// A convenient type alias that assumes the standard claims are sufficient, the empty tuple type
/// satisfies Claims' generic parameter as simply and clearly as possible.
pub type DefaultClaims = Claims<()>;

impl<T: Serialize + Deserialize + PartialEq> Claims<T> {
    /// This implementation simply parses the base64 data twice, first parsing out the standard
    /// claims then any custom claims, assigning the latter into a copy of the former before returning
    /// registered and custom claims.
    pub fn from_base64(raw: &str) -> Result<Claims<T>> {
        let data = decode_config(raw, URL_SAFE_NO_PAD)?;

        let claims: Claims<T> = serde_json::from_slice(&data)?;

        let custom: Option<T> = serde_json::from_slice(&data).ok();

        Ok(Claims {
            iss: claims.iss,
            sub: claims.sub,
            aud: claims.aud,
            exp: claims.exp,
            nbf: claims.nbf,
            iat: claims.iat,
            jti: claims.jti,
            custom: custom,
        })
    }

    /// Renders both the standard and custom claims into a single consolidated JSON representation
    /// before encoding.
    pub fn to_base64(&self) -> Result<String> {
        if let Value::Object(mut claims_map) = serde_json::to_value(&self)? {
            match self.custom {
                Some(ref custom) => {
                    if let Value::Object(custom_map) = serde_json::to_value(&custom)? {
                        claims_map.extend(custom_map);
                        let s = serde_json::to_string(&claims_map)?;
                        let enc = encode_config((&*s).as_bytes(), URL_SAFE_NO_PAD);
                        Ok(enc)
                    } else {
                        Err(Error::Custom("Could not access custom claims.".to_owned()))
                    }
                },
                None => {
                    let s = serde_json::to_string(&claims_map)?;
                    let enc = encode_config((&*s).as_bytes(), URL_SAFE_NO_PAD);
                    return Ok(enc);
                },
            }
        } else {
            Err(Error::Custom("Could not access standard claims.".to_owned()))
        }

    }
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use super::{Claims, DefaultClaims};

    #[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
    struct CustomClaims {
        user_id: String,
        is_admin: bool,
        first_name: Option<String>,
        last_name: Option<String>
    }

    #[test]
    fn from_base64() {
        let enc = "eyJhdWQiOiJsb2dpbl9zZXJ2aWNlIiwiZXhwIjoxMzAyMzE5MTAwLCJpYXQiOjEzMDIzMTcxMDAsImlzcyI6ImV4YW1wbGUuY29tIiwibmJmIjoxMzAyMzE3MTAwLCJzdWIiOiJSYW5kb20gVXNlciJ9";
        let claims: DefaultClaims = Claims::from_base64(enc).unwrap();

        assert_eq!(claims, create_default());
    }

    #[test]
    fn custom_from_base64() {
        let enc = "eyJleHAiOjEzMDIzMTkxMDAsImZpcnN0X25hbWUiOiJSYW5kb20iLCJpYXQiOjEzMDIzMTcxMDAsImlzX2FkbWluIjpmYWxzZSwiaXNzIjoiZXhhbXBsZS5jb20iLCJsYXN0X25hbWUiOiJVc2VyIiwidXNlcl9pZCI6IjEyMzQ1NiJ9";
        let claims: Claims<CustomClaims> = Claims::from_base64(enc).unwrap();

        assert_eq!(claims, create_custom());
    }

    #[test]
    fn to_base64() {
        let enc = "eyJhdWQiOiJsb2dpbl9zZXJ2aWNlIiwiZXhwIjoxMzAyMzE5MTAwLCJpYXQiOjEzMDIzMTcxMDAsImlzcyI6ImV4YW1wbGUuY29tIiwibmJmIjoxMzAyMzE3MTAwLCJzdWIiOiJSYW5kb20gVXNlciJ9";
        let claims = create_default();

        assert_eq!(enc, claims.to_base64().unwrap());
    }

    #[test]
    fn custom_to_base64() {
        let enc = "eyJleHAiOjEzMDIzMTkxMDAsImZpcnN0X25hbWUiOiJSYW5kb20iLCJpYXQiOjEzMDIzMTcxMDAsImlzX2FkbWluIjpmYWxzZSwiaXNzIjoiZXhhbXBsZS5jb20iLCJsYXN0X25hbWUiOiJVc2VyIiwidXNlcl9pZCI6IjEyMzQ1NiJ9";
        let claims = create_custom();

        assert_eq!(enc, claims.to_base64().unwrap());
    }

    #[test]
    fn roundtrip() {
        let claims = create_default();
        let enc = claims.to_base64().unwrap();
        assert_eq!(claims, Claims::from_base64(&*enc).unwrap());
    }

    #[test]
    fn roundtrip_custom() {
        let claims = create_custom();
        let enc = claims.to_base64().unwrap();
        assert_eq!(claims, Claims::<CustomClaims>::from_base64(&*enc).unwrap());
    }

    fn create_default() -> DefaultClaims {
        DefaultClaims {
            aud: Some("login_service".into()),
            iat: Some(1302317100),
            iss: Some("example.com".into()),
            exp: Some(1302319100),
            nbf: Some(1302317100),
            sub: Some("Random User".into()),
            ..Default::default()
        }
    }

    fn create_custom() -> Claims<CustomClaims> {
        Claims {
            iss: Some("example.com".into()),
            iat: Some(1302317100),
            exp: Some(1302319100),
            custom: Some(CustomClaims {
                user_id: "123456".into(),
                is_admin: false,
                first_name: Some("Random".into()),
                last_name: Some("User".into()),
            }),
            ..Default::default()
        }
    }
}
