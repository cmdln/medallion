use medallion::{Header, Payload, Token};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Custom {
    user_id: String,
    // useful if you want a None to not appear in the serialized JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    rhino: bool,
}

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // dummy auth, in a real application using something like openidconnect, this would be some
    // specific authentication scheme that takes place first then the JWT is generated as part of
    // sucess and signed with the provider's private key so other services can validate trust for
    // the claims in the token
    if password != "password" {
        return None;
    }

    let header: Header = Header::default();
    let payload = Payload {
        // custom claims will be application specific, they may come from open standards such as
        // openidconnect where they may be referred to as registered claims
        claims: Some(Custom {
            user_id: user_id.into(),
            rhino: true,
            ..Custom::default()
        }),
        ..Payload::default()
    };
    let token = Token::new(header, payload);

    token.sign(b"secret_key").ok()
}

fn login(token: &str) -> Option<String> {
    let token = Token::<(), Custom>::parse(token).unwrap();

    if token.verify(b"secret_key").unwrap() {
        Some(token.payload.claims.unwrap().user_id)
    } else {
        None
    }
}

fn main() {
    let token = new_token("Random User", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Random User");
}
