extern crate medallion;

use std::default::Default;
use medallion::{
    DefaultHeader,
    Registered,
    Token,
};

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None
    }

    let header: DefaultHeader = Default::default();
    let claims = Registered {
        iss: Some("example.com".into()),
        sub: Some(user_id.into()),
        ..Default::default()
    };
    let token = Token::new(header, claims);

    token.signed(b"secret_key").ok()
}

fn login(token: &str) -> Option<String> {
    let token = Token::<DefaultHeader, Registered>::parse(token).unwrap();

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
