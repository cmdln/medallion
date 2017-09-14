use base64::Base64Error;
use serde_json;
use std::error;
use std::fmt;
use std::string::FromUtf8Error;
use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum Error {
    /// Custom, Medallion specific errors.
    Custom(String),
    /// String encoding errors.
    Utf8(FromUtf8Error),
    /// Base64 encoding or decoding errors.
    Base64(Base64Error),
    /// JSON parsing or stringifying errors.
    JSON(serde_json::Error),
    /// Errors from RSA operations.
    Crypto(ErrorStack),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Custom(ref message) => message,
            Error::Utf8(ref err) => err.description(),
            Error::Base64(ref err) => err.description(),
            Error::JSON(ref err) => err.description(),
            Error::Crypto(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Custom(_) => None,
            Error::Utf8(ref err) => Some(err),
            Error::Base64(ref err) => Some(err),
            Error::JSON(ref err) => Some(err),
            Error::Crypto(ref err) => Some(err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Custom(ref message) => f.write_str(message),
            Error::Utf8(ref err) => err.fmt(f),
            Error::Base64(ref err) => err.fmt(f),
            Error::JSON(ref err) => err.fmt(f),
            Error::Crypto(ref err) => err.fmt(f),
        }
    }
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
error_wrap!(ErrorStack, Error::Crypto);
