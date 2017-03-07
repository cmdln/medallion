// need this for custom derivation
#[macro_use]
extern crate serde_derive;
extern crate medallion;

use std::default::Default;
use medallion::{Claims, Header, Token};

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Custom {
    user_id: String,
    // useful if you want a None to not appear in the serialized JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    rhino: bool,
}

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None;
    }

    let header: Header<()> = Default::default();
    let claims = Claims {
        custom: Some(Custom {
            user_id: user_id.into(),
            rhino: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    let token = Token::new(header, claims);

    token.sign(b"secret_key").ok()
}

fn login(token: &str) -> Option<String> {
    let token = Token::<(), Custom>::parse(token).unwrap();

    if token.verify(b"secret_key").unwrap() {
        Some(token.claims.custom.unwrap().user_id)
    } else {
        None
    }
}

fn main() {
    let token = new_token("Random User", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Random User");
}
