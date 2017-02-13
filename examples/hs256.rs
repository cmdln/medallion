extern crate crypto;
extern crate jwt;

use std::default::Default;
use jwt::{
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
        iss: Some("mikkyang.com".into()),
        sub: Some(user_id.into()),
        ..Default::default()
    };
    let token = Token::new(header, claims);

    token.signed(b"secret_key").ok()
}

fn login(token: &str) -> Option<String> {
    let token = Token::<DefaultHeader, Registered>::parse(token).unwrap();

    if token.verify(b"secret_key") {
        token.claims.sub
    } else {
        None
    }
}

fn main() {
    let token = new_token("Michael Yang", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Michael Yang");
}
