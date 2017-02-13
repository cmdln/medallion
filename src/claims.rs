use base64::{decode, encode_config, URL_SAFE};
use Component;
use error::Error;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::value::{from_value, to_value, Map, Value};

#[derive(Debug, Default, PartialEq)]
pub struct Claims {
    pub reg: Registered,
    pub private: Value
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

/// JWT Claims. Registered claims are directly accessible via the `Registered`
/// struct embedded, while private fields are a map that contains `Json`
/// values.
impl Claims {
    pub fn new(reg: Registered, private: Value) -> Claims {
        Claims {
            reg: reg,
            private: private
        }
    }
}

impl Component for Claims {
    fn from_base64(raw: &str) -> Result<Claims, Error> {
        let data = try!(decode(raw));
        let reg_claims: Registered = try!(serde_json::from_slice(&data));

        let pri_claims: Value = try!(serde_json::from_slice(&data));


        Ok(Claims{
            reg: reg_claims,
            private: pri_claims
        })
    }

    fn to_base64(&self) -> Result<String, Error> {
        let mut value = try!(serde_json::to_value(&self.reg));
        let mut obj_value = &value.as_object_mut().unwrap();
        // TODO iterate private claims and add to JSON Map
        //let mut pri_value = self.private.as_object_mut().unwrap();

        //obj_value.extend(pri_value.into_iter());

        let s = try!(serde_json::to_string(&obj_value));
        let enc = encode_config((&*s).as_bytes(), URL_SAFE);
        Ok(enc)
    }
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use claims::{Claims, Registered};
    use Component;

    #[test]
    fn from_base64() {
        let enc = "ew0KICAiaXNzIjogIm1pa2t5YW5nLmNvbSIsDQogICJleHAiOiAxMzAyMzE5MTAwLA0KICAibmFtZSI6ICJNaWNoYWVsIFlhbmciLA0KICAiYWRtaW4iOiB0cnVlDQp9";
        let claims = Claims::from_base64(enc).unwrap();

        assert_eq!(claims.reg.iss.unwrap(), "mikkyang.com");
        assert_eq!(claims.reg.exp.unwrap(), 1302319100);
    }

    #[test]
    fn multiple_types() {
        let enc = "ew0KICAiaXNzIjogIm1pa2t5YW5nLmNvbSIsDQogICJleHAiOiAxMzAyMzE5MTAwLA0KICAibmFtZSI6ICJNaWNoYWVsIFlhbmciLA0KICAiYWRtaW4iOiB0cnVlDQp9";
        let claims = Registered::from_base64(enc).unwrap();

        assert_eq!(claims.iss.unwrap(), "mikkyang.com");
        assert_eq!(claims.exp.unwrap(), 1302319100);
    }

    #[test]
    fn roundtrip() {
        let mut claims: Claims = Default::default();
        claims.reg.iss = Some("mikkyang.com".into());
        claims.reg.exp = Some(1302319100);
        let enc = claims.to_base64().unwrap();
        assert_eq!(claims, Claims::from_base64(&*enc).unwrap());
    }
}
