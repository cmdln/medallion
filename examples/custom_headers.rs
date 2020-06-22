use medallion::{DefaultPayload, DefaultToken, Header};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
struct Custom {
    // useful if you want a None to not appear in the serialized JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    typ: String,
}

fn new_token(sub: &str, password: &str) -> Option<String> {
    // dummy auth, in a real application using something like openidconnect, this would be some
    // specific authentication scheme that takes place first then the JWT is generated as part of
    // sucess and signed with the provider's private key so other services can validate trust for
    // the claims in the token
    if password != "password" {
        return None;
    }

    let header = Header {
        // customer headers generally are about the token itself, like here describing the type of
        // token, as opposed to claims which are about the authenticated user or some output of
        // the authentication process
        headers: Some(Custom {
            typ: "JWT".into(),
            ..Custom::default()
        }),
        ..Default::default()
    };
    let payload = DefaultPayload {
        sub: Some(sub.into()),
        ..DefaultPayload::default()
    };
    let token = DefaultToken::new(header, payload);

    token.sign(b"secret_key").ok()
}

fn login(token: &str) -> Option<String> {
    let token = DefaultToken::<Custom>::parse(token).unwrap();

    if token.verify(b"secret_key").unwrap() {
        Some(token.payload.sub.unwrap())
    } else {
        None
    }
}

fn main() {
    let token = new_token("Random User", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Random User");
}
