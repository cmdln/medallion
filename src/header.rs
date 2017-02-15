use std::default::Default;
use Header;

/// A default Header providing the type, key id and algorithm fields.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DefaultHeader {
    pub typ: Option<HeaderType>,
    pub kid: Option<String>,
    pub alg: Algorithm,
}


/// Default value for the header type field.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum HeaderType {
    JWT,
}

/// Supported algorithms, each representing a valid signature and digest combination.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512
}

impl Default for DefaultHeader {
    fn default() -> DefaultHeader {
        DefaultHeader {
            typ: Some(HeaderType::JWT),
            kid: None,
            alg: Algorithm::HS256,
        }
    }
}

/// Allow the rest of the library to access the configured algorithm without having to know the
/// specific type for the header.
impl Header for DefaultHeader {
    fn alg(&self) -> &Algorithm {
        &(self.alg)
    }
}

#[cfg(test)]
mod tests {
    use Component;
    use header::{
        Algorithm,
        DefaultHeader,
        HeaderType,
    };

    #[test]
    fn from_base64() {
        let enc = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let header = DefaultHeader::from_base64(enc).unwrap();

        assert_eq!(header.typ.unwrap(), HeaderType::JWT);
        assert_eq!(header.alg, Algorithm::HS256);


        let enc = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFLU0YzZyJ9";
        let header = DefaultHeader::from_base64(enc).unwrap();

        assert_eq!(header.kid.unwrap(), "1KSF3g".to_string());
        assert_eq!(header.alg, Algorithm::RS256);
    }

    #[test]
    fn roundtrip() {
        let header: DefaultHeader = Default::default();
        let enc = Component::to_base64(&header).unwrap();
        assert_eq!(header, DefaultHeader::from_base64(&*enc).unwrap());
    }
}
