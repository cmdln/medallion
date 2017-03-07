extern crate medallion;

use std::default::Default;
use std::fs::File;
use std::io::{Error, Read};
use medallion::{Algorithm, Header, DefaultPayload, DefaultToken};

fn load_pem(keypath: &str) -> Result<String, Error> {
    let mut key_file = File::open(keypath)?;
    let mut key = String::new();
    key_file.read_to_string(&mut key)?;
    Ok(key)
}

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None;
    }

    // can satisfy Header's generic parameter with an empty type
    let header: Header<()> = Header { alg: Algorithm::RS256, ..Default::default() };
    let payload: DefaultPayload = DefaultPayload {
        iss: Some("example.com".into()),
        sub: Some(user_id.into()),
        ..Default::default()
    };
    let token = DefaultToken::new(header, payload);

    // this key was generated explicitly for these examples and is not used anywhere else
    token.sign(load_pem("./privateKey.pem").unwrap().as_bytes()).ok()
}

fn login(token: &str) -> Option<String> {
    let token: DefaultToken<()> = DefaultToken::parse(token).unwrap();

    // this key was generated explicitly for these examples and is not used anywhere else
    if token.verify(load_pem("./publicKey.pub").unwrap().as_bytes()).unwrap() {
        token.payload.sub
    } else {
        None
    }
}

fn main() {
    let token = new_token("Random User", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Random User");
}
