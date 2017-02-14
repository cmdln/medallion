use base64::{decode_config, encode_config, URL_SAFE};
use Component;
use error::Error;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::value::{Value};

#[derive(Debug, Default, PartialEq)]
pub struct Claims<T: Serialize + Deserialize> {
    pub reg: Registered,
    pub private: T
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Registered {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub jti: Option<String>,
}

impl<T: Serialize + Deserialize> Claims<T>{
    pub fn new(reg: Registered, private: T) -> Claims<T> {
        Claims {
            reg: reg,
            private: private
        }
    }
}

impl<T: Serialize + Deserialize> Component for Claims<T> {
    fn from_base64(raw: &str) -> Result<Claims<T>, Error> {
        let data = try!(decode_config(raw, URL_SAFE));
        let reg_claims: Registered = try!(serde_json::from_slice(&data));

        let pri_claims: T = try!(serde_json::from_slice(&data));


        Ok(Claims {
            reg: reg_claims,
            private: pri_claims
        })
    }

    fn to_base64(&self) -> Result<String, Error> {
        if let Value::Object(mut reg_map) = serde_json::to_value(&self.reg)? {
            if let Value::Object(pri_map) = serde_json::to_value(&self.private)? {
                reg_map.extend(pri_map);
                let s = try!(serde_json::to_string(&reg_map));
                let enc = encode_config((&*s).as_bytes(), URL_SAFE);
                Ok(enc)
            } else {
                Err(Error::Custom("Could not access registered claims.".to_owned()))
            }
        } else {
            Err(Error::Custom("Could not access private claims.".to_owned()))
        }

    }
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use claims::{Claims, Registered};
    use Component;

    #[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
    struct EmptyClaim { }

    #[test]
    fn from_base64() {
        let enc = "ew0KICAiaXNzIjogIm1pa2t5YW5nLmNvbSIsDQogICJleHAiOiAxMzAyMzE5MTAwLA0KICAibmFtZSI6ICJNaWNoYWVsIFlhbmciLA0KICAiYWRtaW4iOiB0cnVlDQp9";
        let claims: Claims<EmptyClaim> = Claims::from_base64(enc).unwrap();

        assert_eq!(claims.reg.iss.unwrap(), "mikkyang.com");
        assert_eq!(claims.reg.exp.unwrap(), 1302319100);
    }

    #[test]
    fn multiple_types() {
        let enc = "ew0KICAiaXNzIjogIm1pa2t5YW5nLmNvbSIsDQogICJleHAiOiAxMzAyMzE5MTAwLA0KICAibmFtZSI6ICJNaWNoYWVsIFlhbmciLA0KICAiYWRtaW4iOiB0cnVlDQp9";
        let claims  = Registered::from_base64(enc).unwrap();

        assert_eq!(claims.iss.unwrap(), "mikkyang.com");
        assert_eq!(claims.exp.unwrap(), 1302319100);
    }

    #[test]
    fn roundtrip() {
        let mut claims: Claims<EmptyClaim> = Default::default();
        claims.reg.iss = Some("mikkyang.com".into());
        claims.reg.exp = Some(1302319100);
        let enc = claims.to_base64().unwrap();
        assert_eq!(claims, Claims::from_base64(&*enc).unwrap());
    }
}
