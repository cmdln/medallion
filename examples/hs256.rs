extern crate medallion;

use std::default::Default;
use medallion::{Header, DefaultClaims, DefaultToken};

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None;
    }

    // can satisfy Header's generic parameter with an empty type
    let header: Header<()> = Default::default();
    let claims = DefaultClaims {
        iss: Some("example.com".into()),
        sub: Some(user_id.into()),
        ..Default::default()
    };
    let token = DefaultToken::new(header, claims);

    token.sign(b"secret_key").ok()
}

fn login(token: &str) -> Option<String> {
    let token: DefaultToken<()> = DefaultToken::parse(token).unwrap();

    if token.verify(b"secret_key").unwrap() {
        token.claims.sub
    } else {
        None
    }
}

fn main() {
    let token = new_token("Random User", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Random User");
}
