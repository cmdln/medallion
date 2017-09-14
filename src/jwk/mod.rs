use serde::{Serialize, Serializer};
use serde::de::DeserializeOwned;
use serde::ser::{self, SerializeMap};
use serde_json::{self, Value};
use std;
use Result;

mod rsa;
mod octet;

pub use self::rsa::RsaParams;
pub use self::octet::OctetSequenceParams;


/// Support keytypes.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    /// RSA asymmetric keys, public and private both.
    RSA,
    /// Simple symmetric keys, for instance used with HMAC.
    OCT,
}

#[derive(Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeySet {
    keys: Vec<Value>,
}

impl KeySet {
    pub fn new() -> KeySet {
        KeySet { ..Default::default() }
    }

    pub fn push<T>(&mut self, key: Key<T>)
        where T: Serialize
    {
        self.keys.push(serde_json::to_value(key).unwrap());
    }

    pub fn pop<T>(&mut self) -> Result<Key<T>>
        where T: DeserializeOwned
    {
        let value = self.keys.pop().unwrap();

        let key: Key<T> = serde_json::from_value(value.clone())?;

        let params: Option<T> = serde_json::from_value(value)?;

        Ok(Key {
            kty: key.kty,
            kid: key.kid,
            params: params,
        })
    }

    // TODO store map of kid to key
    // TODO replace pop with get by kid
    // TODO expose iterator over kid

    pub fn to_string(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }

    pub fn from_string(raw: &str) -> Result<Self> {
        Ok(serde_json::from_str(raw)?)
    }
}

/// Generic key that composes parameters for different specific types, like RSA and Octet Sequence.
#[derive(Debug, PartialEq, Deserialize)]
pub struct Key<T> {
    pub kty: KeyType,
    pub kid: String,
    pub params: Option<T>,
}

impl<T: Serialize + DeserializeOwned> Key<T> {
    // TODO deprecate in favor of serde
    pub fn to_string(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }

    // TODO implement custom serde de-serializer
    // TODO deprecate in favor of serde
    pub fn from_string(raw: &str) -> Result<Self> {
        let key: Key<T> = serde_json::from_str(raw)?;

        let params: Option<T> = serde_json::from_str(raw)?;

        Ok(Key {
            kty: key.kty,
            kid: key.kid,
            params: params,
        })
    }
}

impl<T: Serialize> Serialize for Key<T> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where S: Serializer
    {
        if let Some(ref params) = self.params {
            // TODO is there a simpler/better way to get a Map?
            if let Ok(Value::Object(params_map)) = serde_json::to_value(params) {
                let mut map = serializer.serialize_map(Some(params_map.len() + 2))?;
                map.serialize_entry("kty", &self.kty)?;
                map.serialize_entry("kid", &self.kid)?;
                for (k, v) in params_map {
                    map.serialize_entry(&k, &v)?;
                }
                map.end()
            } else {
                Err(ser::Error::custom("Unable to access parameters!"))
            }
        } else {
            Err(ser::Error::custom("No parameters!"))
        }
    }
}

#[cfg(test)]
mod tests {
    use openssl::rsa::Rsa;
    use {Algorithm, KeySet, KeyType, OctetSequenceKey, OctetSequenceParams, RsaPublicKey, RsaParams};

    #[test]
    pub fn rsa_private_key() {
        let rsa_keypair = Rsa::generate(2048).unwrap();
        let params = RsaParams::from_private_key_pem(&rsa_keypair.private_key_to_pem().unwrap())
            .unwrap();
        let key = RsaPublicKey {
            kty: KeyType::RSA,
            kid: "foo".to_owned(),
            params: Some(params),
        };

        let json = key.to_string().unwrap();
        println!("{}", json);
        let recovered = RsaPublicKey::from_string(&json).unwrap();
        assert_eq!(key, recovered);
    }

    #[test]
    pub fn rsa_public_key() {
        let rsa_keypair = Rsa::generate(2048).unwrap();
        let params = RsaParams::from_public_key_pem(&rsa_keypair.public_key_to_pem().unwrap()).unwrap();
        let key = RsaPublicKey {
            kty: KeyType::RSA,
            kid: "bar".to_owned(),
            params: Some(params),
        };

        let json = key.to_string().unwrap();
        println!("{}", json);
        let recovered = RsaPublicKey::from_string(&json).unwrap();
        assert_eq!(key, recovered);
    }

    #[test]
    pub fn octet_key() {
        let key = OctetSequenceKey {
            kty: KeyType::OCT,
            kid: "baz".to_owned(),
            params: Some(OctetSequenceParams::from_slice(Algorithm::HS512, b"super secret key")),
        };
        let json = key.to_string().unwrap();
        println!("{}", json);
        let recovered = OctetSequenceKey::from_string(&json).unwrap();
        assert_eq!(key, recovered);
    }

    #[test]
    pub fn key_set() {
        let key1 = OctetSequenceKey {
            kty: KeyType::OCT,
            kid: "baz".to_owned(),
            params: Some(OctetSequenceParams::from_slice(Algorithm::HS512, b"super secret key")),
        };

        let rsa_keypair = Rsa::generate(2048).unwrap();
        let params = RsaParams::from_public_key_pem(&rsa_keypair.public_key_to_pem().unwrap()).unwrap();
        let key2 = RsaPublicKey {
            kty: KeyType::RSA,
            kid: "bar".to_owned(),
            params: Some(params),
        };

        let mut key_set = KeySet::new();

        key_set.push(key1);
        key_set.push(key2);

        let key1 = OctetSequenceKey {
            kty: KeyType::OCT,
            kid: "baz".to_owned(),
            params: Some(OctetSequenceParams::from_slice(Algorithm::HS512, b"super secret key")),
        };

        let params = RsaParams::from_public_key_pem(&rsa_keypair.public_key_to_pem().unwrap()).unwrap();
        let key2 = RsaPublicKey {
            kty: KeyType::RSA,
            kid: "bar".to_owned(),
            params: Some(params),
        };

        let mut recovered = KeySet::from_string(&key_set.to_string().unwrap()).unwrap();

        assert_eq!(key2, recovered.pop::<RsaParams>().unwrap());
        assert_eq!(key1, recovered.pop::<OctetSequenceParams>().unwrap());
    }
}
