use super::Result;
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json;
use serde_json::value::Value;
use time::{self, Timespec};

/// A default claim set, including the standard, or registered, claims and the ability to specify
/// your own as custom claims.
#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct Payload<T = ()> {
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
    pub claims: Option<T>,
}

/// A convenient type alias that assumes the standard claims are sufficient, the empty tuple type
/// satisfies Claims' generic parameter as simply and clearly as possible.
pub type DefaultPayload = Payload<()>;

impl<T: Serialize + DeserializeOwned> Payload<T> {
    /// This implementation simply parses the base64 data twice, first parsing out the standard
    /// claims then any custom claims, assigning the latter into a copy of the former before
    /// returning registered and custom claims.
    pub fn from_base64(raw: &str) -> Result<Payload<T>> {
        let data = decode_config(raw, URL_SAFE_NO_PAD)?;

        let claims: Payload<T> = serde_json::from_slice(&data)?;

        let custom: Option<T> = serde_json::from_slice(&data).ok();

        Ok(Payload {
            iss: claims.iss,
            sub: claims.sub,
            aud: claims.aud,
            exp: claims.exp,
            nbf: claims.nbf,
            iat: claims.iat,
            jti: claims.jti,
            claims: custom,
        })
    }

    /// Renders both the standard and custom claims into a single consolidated JSON representation
    /// before encoding.
    pub fn to_base64(&self) -> Result<String> {
        if let Value::Object(mut claims_map) = serde_json::to_value(&self)? {
            match self.claims {
                Some(ref custom) => {
                    if let Value::Object(custom_map) = serde_json::to_value(&custom)? {
                        claims_map.extend(custom_map);
                        let s = serde_json::to_string(&claims_map)?;
                        let enc = encode_config((&*s).as_bytes(), URL_SAFE_NO_PAD);
                        Ok(enc)
                    } else {
                        Err(format_err!("Could not access custom claims."))
                    }
                }
                None => {
                    let s = serde_json::to_string(&claims_map)?;
                    let enc = encode_config((&*s).as_bytes(), URL_SAFE_NO_PAD);
                    return Ok(enc);
                }
            }
        } else {
            Err(format_err!("Could not access standard claims.",))
        }
    }

    pub fn verify(&self) -> bool {
        let now = time::now().to_timespec();
        let nbf_verified = match self.nbf {
            Some(nbf_sec) => Timespec::new(nbf_sec as i64, 0) < now,
            None => true,
        };
        let exp_verified = match self.exp {
            Some(exp_sec) => now < Timespec::new(exp_sec as i64, 0),
            None => true,
        };
        nbf_verified && exp_verified
    }
}

#[cfg(test)]
mod tests {
    use super::{DefaultPayload, Payload};
    use std::default::Default;
    use time::{self, Duration};

    #[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
    struct CustomClaims {
        user_id: String,
        is_admin: bool,
        first_name: Option<String>,
        last_name: Option<String>,
    }

    #[test]
    fn from_base64() {
        let enc = "eyJhdWQiOiJsb2dpbl9zZXJ2aWNlIiwiZXhwIjoxMzAyMzE5MTAwLCJpYXQiOjEzMDIzMTcxMDAsImlzcyI6ImV4YW1wbGUuY29tIiwibmJmIjoxMzAyMzE3MTAwLCJzdWIiOiJSYW5kb20gVXNlciJ9";
        let payload: DefaultPayload = Payload::from_base64(enc).unwrap();

        assert_eq!(payload, create_default());
    }

    #[test]
    fn custom_from_base64() {
        let enc = "eyJleHAiOjEzMDIzMTkxMDAsImZpcnN0X25hbWUiOiJSYW5kb20iLCJpYXQiOjEzMDIzMTcxMDAsImlzX2FkbWluIjpmYWxzZSwiaXNzIjoiZXhhbXBsZS5jb20iLCJsYXN0X25hbWUiOiJVc2VyIiwidXNlcl9pZCI6IjEyMzQ1NiJ9";
        let payload: Payload<CustomClaims> = Payload::from_base64(enc).unwrap();

        assert_eq!(payload, create_custom());
    }

    #[test]
    fn to_base64() {
        let enc = "eyJhdWQiOiJsb2dpbl9zZXJ2aWNlIiwiZXhwIjoxMzAyMzE5MTAwLCJpYXQiOjEzMDIzMTcxMDAsImlzcyI6ImV4YW1wbGUuY29tIiwibmJmIjoxMzAyMzE3MTAwLCJzdWIiOiJSYW5kb20gVXNlciJ9";
        let payload = create_default();

        assert_eq!(enc, payload.to_base64().unwrap());
    }

    #[test]
    fn custom_to_base64() {
        let enc = "eyJleHAiOjEzMDIzMTkxMDAsImZpcnN0X25hbWUiOiJSYW5kb20iLCJpYXQiOjEzMDIzMTcxMDAsImlzX2FkbWluIjpmYWxzZSwiaXNzIjoiZXhhbXBsZS5jb20iLCJsYXN0X25hbWUiOiJVc2VyIiwidXNlcl9pZCI6IjEyMzQ1NiJ9";
        let payload = create_custom();

        assert_eq!(enc, payload.to_base64().unwrap());
    }

    #[test]
    fn roundtrip() {
        let payload = create_default();
        let enc = payload.to_base64().unwrap();
        assert_eq!(payload, Payload::from_base64(&*enc).unwrap());
    }

    #[test]
    fn roundtrip_custom() {
        let payload = create_custom();
        let enc = payload.to_base64().unwrap();
        assert_eq!(
            payload,
            Payload::<CustomClaims>::from_base64(&*enc).unwrap()
        );
    }

    #[test]
    fn verify_nbf() {
        let payload = create_with_nbf(5);
        assert!(payload.verify());
    }

    #[test]
    fn fail_nbf() {
        let payload = create_with_nbf(-5);
        assert_eq!(false, payload.verify());
    }

    #[test]
    fn verify_exp() {
        let payload = create_with_exp(5);
        assert!(payload.verify());
    }

    #[test]
    fn fail_exp() {
        let payload = create_with_exp(-5);
        assert_eq!(false, payload.verify());
    }

    #[test]
    fn verify_nbf_exp() {
        let payload = create_with_nbf_exp(5, 5);
        assert!(payload.verify());
    }

    #[test]
    fn fail_nbf_exp() {
        let payload = create_with_nbf_exp(-5, -5);
        assert_eq!(false, payload.verify());
        let payload = create_with_nbf_exp(5, -5);
        assert_eq!(false, payload.verify());
        let payload = create_with_nbf_exp(-5, 5);
        assert_eq!(false, payload.verify());
    }

    fn create_with_nbf(offset: i64) -> DefaultPayload {
        let nbf = (time::now() - Duration::minutes(offset)).to_timespec().sec;
        DefaultPayload {
            nbf: Some(nbf as u64),
            ..Default::default()
        }
    }

    fn create_with_exp(offset: i64) -> DefaultPayload {
        let exp = (time::now() + Duration::minutes(offset)).to_timespec().sec;
        DefaultPayload {
            exp: Some(exp as u64),
            ..Default::default()
        }
    }

    fn create_with_nbf_exp(nbf_offset: i64, exp_offset: i64) -> DefaultPayload {
        let nbf = (time::now() - Duration::minutes(nbf_offset))
            .to_timespec()
            .sec;
        let exp = (time::now() + Duration::minutes(exp_offset))
            .to_timespec()
            .sec;
        DefaultPayload {
            nbf: Some(nbf as u64),
            exp: Some(exp as u64),
            ..Default::default()
        }
    }

    fn create_default() -> DefaultPayload {
        DefaultPayload {
            aud: Some("login_service".into()),
            iat: Some(1_302_317_100),
            iss: Some("example.com".into()),
            exp: Some(1_302_319_100),
            nbf: Some(1_302_317_100),
            sub: Some("Random User".into()),
            ..Default::default()
        }
    }

    fn create_custom() -> Payload<CustomClaims> {
        Payload {
            iss: Some("example.com".into()),
            iat: Some(1_302_317_100),
            exp: Some(1_302_319_100),
            claims: Some(CustomClaims {
                user_id: "123456".into(),
                is_admin: false,
                first_name: Some("Random".into()),
                last_name: Some("User".into()),
            }),
            ..Default::default()
        }
    }
}
