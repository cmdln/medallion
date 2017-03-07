Medallion
=========
[![Build Status](https://travis-ci.org/commandline/medallion.svg?branch=master)](https://travis-ci.org/commandline/medallion)
[![Crates.io Status](http://meritbadge.herokuapp.com/medallion)](https://crates.io/crates/medallion)
[![Documentation](https://docs.rs/medallion/badge.svg)](https://docs.rs/medallion)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/commandline/medallion/master/LICENSE)

A JWT library for rust using serde, serde_json and openssl.

## Documentation

- [Documentation] (https://commandline.github.io/medallion/)

## Usage

The library provides a `Token` type that wraps headers and claims.

```rust
extern crate medallion;

use std::default::Default;

use medallion::{
    Header,
    DefaultPayload,
    Token,
};

fn main() {
    // will default to Algorithm::HS256
    let header: Header<()> = Default::default();
    let payload = DefaultPayload {
        iss: Some("example.com".into()),
        sub: Some("Random User".into()),
        ..Default::default()
    };
    let token = Token::new(header, payload);

    token.sign(b"secret_key").unwrap();
}
```

The `Header` struct contains all of the headers of the JWT. It requires that a supported algorithm (`HS256`, `HS384`, `HS512`, `RS256`, `RS384`, and `RS512`) be specified. It requires a type for additional header fields. That type must implement serde's `Serialize` and `Deserialize` as well as `PartialEq`. These traits can usually be derived, e.g.  `#[derive(PartialEq, Serialize, Deserialize)`.

```rust
extern crate medallion;

use std::default::Default;
use serde::{Serialize, Deserialize};

use medallion::{Header, DefaultPayload, Token};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct CustomHeaders {
    kid: String,
    typ: String,
}

fn main() {
    let header = Header {
        headers: CustomHeaders {
            kid: "0001",)
            typ: "JWT",)
        }
        ..Default::default()
    }
    let payload = DefaultPayload {
        iss: Some("example.com".into()),
        sub: Some("Random User".into()),
        ..Default::default()
    };
    let token = Token::new(header, payload);

    token.sign(b"secret_key").unwrap();
}
```

The `Payload` struct contains all of the claims of the JWT. It provides the set of registered, public claims. Additional claims can be added by constructing the `Payload` with a generically typed value. That value's type must implement serde's `Serialize` and `Deserialize` as well as `PartialEq`. These traits can usually be derived, e.g.  `#[derive(PartialEq, Serialize, Deserialize)`. A convenience type, `DefaultPayload`, is provided that binds the generic parameter of `Payload` to an empty tuple type.

```rust
extern crate medallion;

use std::default::Default;
use serde::{Serialize, Deserialize};

use medallion::{Header, DefaultPayload, Token};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct CustomHeaders {
    kid: String,
    typ: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct CustomClaims {
    user_id: u64,
    email: String,
}

fn main() {
    let header = Header {
        headers: CustomHeaders {
            kid: "0001",)
            typ: "JWT",)
        }
        ..Default::default()
    }
    let payload = DefaultPayload {
        iss: Some("example.com".into()),
        sub: Some("Random User".into()),
        claims: CustomClaims {
            user_id: 1234,
            email: "random@example.com",
        }
        ..Default::default()
    };
    let token = Token::new(header, payload);

    token.sign(b"secret_key").unwrap();
}
```

See the examples for more detailed usage.

This library was originally forked from @mikkyang's rust-jwt.
