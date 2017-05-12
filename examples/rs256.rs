extern crate medallion;
extern crate openssl;

use std::default::Default;
use openssl::rsa;
use medallion::{Algorithm, Header, DefaultPayload, DefaultToken};

fn new_token(private_key: &[u8], user_id: &str, password: &str) -> Option<String> {
    // dummy auth, in a real application using something like openidconnect, this would be some
    // specific authentication scheme that takes place first then the JWT is generated as part of
    // sucess and signed with the provider's private key so other services can validate trust for
    // the claims in the token
    if password != "password" {
        return None;
    }

    // can satisfy Header's type parameter with an empty tuple
    let header: Header<()> = Header { alg: Algorithm::RS256, ..Default::default() };
    let payload: DefaultPayload = DefaultPayload {
        iss: Some("example.com".into()),
        sub: Some(user_id.into()),
        ..Default::default()
    };
    let token = DefaultToken::new(header, payload);

    token.sign(private_key).ok()
}

fn login(public_key: &[u8], token: &str) -> Option<String> {
    let token: DefaultToken<()> = DefaultToken::parse(token).unwrap();

    if token.verify(public_key).unwrap() {
        token.payload.sub
    } else {
        None
    }
}

fn main() {
    // alternatively can read .pem files from fs or fetch from a server or...
    let keypair = rsa::Rsa::generate(2048).unwrap();

    let token = new_token(&keypair.private_key_to_pem().unwrap(), "Random User", "password").unwrap();

    let logged_in_user = login(&keypair.public_key_to_pem().unwrap(), &*token).unwrap();

    assert_eq!(logged_in_user, "Random User");
}
