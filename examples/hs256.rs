extern crate medallion;

use medallion::{DefaultPayload, DefaultToken, Header};

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // dummy auth, in a real application using something like openidconnect, this would be some
    // specific authentication scheme that takes place first then the JWT is generated as part of
    // sucess and signed with the provider's private key so other services can validate trust for
    // the claims in the token
    if password != "password" {
        return None;
    }

    // can satisfy Header's generic parameter with an empty type
    let header: Header = Header::default();
    let payload = DefaultPayload {
        iss: Some("example.com".into()),
        sub: Some(user_id.into()),
        ..DefaultPayload::default()
    };
    let token = DefaultToken::new(header, payload);

    token.sign(b"secret_key").ok()
}

fn login(token: &str) -> Option<String> {
    let token: DefaultToken<()> = DefaultToken::parse(token).unwrap();

    // the key for HMAC is some secret known to trusted/trusting parties
    if token.verify(b"secret_key").unwrap() {
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
