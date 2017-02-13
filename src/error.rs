use base64::Base64Error;
use serde_json;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum Error {
    Format,
    Utf8(FromUtf8Error),
    Base64(Base64Error),
    JSON(serde_json::Error),
}

macro_rules! error_wrap {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}

error_wrap!(FromUtf8Error, Error::Utf8);
error_wrap!(Base64Error, Error::Base64);
error_wrap!(serde_json::Error, Error::JSON);
