// need this for custom derivation
#[macro_use]
extern crate serde_derive;
extern crate medallion;

use std::default::Default;
use medallion::{
    DefaultHeader,
    Token,
};

#[derive(Default, Serialize, Deserialize)]
struct Custom {
    sub: String,
    rhino: bool,
}

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None
    }

    let header: DefaultHeader = Default::default();
    let claims = Custom {
        sub: user_id.into(),
        rhino: true,
        ..Default::default()
    };
    let token = Token::new(header, claims);

    token.signed(b"secret_key").ok()
}

fn login(token: &str) -> Option<String> {
    let token = Token::<DefaultHeader, Custom>::parse(token).unwrap();

    if token.verify(b"secret_key").unwrap() {
        Some(token.claims.sub)
    } else {
        None
    }
}

fn main() {
    let token = new_token("Random User", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Random User");
}
