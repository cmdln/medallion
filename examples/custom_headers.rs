// need this for custom derivation
#[macro_use]
extern crate serde_derive;
extern crate medallion;

use std::default::Default;
use medallion::{
    DefaultClaims,
    Header,
    DefaultToken,
};

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Custom {
    // useful if you want a None to not appear in the serialized JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    typ: String,
}

fn new_token(sub: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None
    }

    let header = Header {
        headers: Some(Custom {
            typ: "JWT".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let claims = DefaultClaims {
        sub: Some(sub.into()),
        ..Default::default()
    };
    let token = DefaultToken::new(header, claims);

    token.sign(b"secret_key").ok()
}

fn login(token: &str) -> Option<String> {
    let token = DefaultToken::<Custom>::parse(token).unwrap();

    if token.verify(b"secret_key").unwrap() {
        Some(token.claims.sub.unwrap())
    } else {
        None
    }
}

fn main() {
    let token = new_token("Random User", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Random User");
}
