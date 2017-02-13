# JWT

A JWT library for rust using serde, serde_json and openssl.

## Usage

The library provides a `Token` type that wraps a header and claims. The claims can be any type that implements the `Component` trait, which is automatically implemented for types that implement the `Sized`, `Encodable`,
and `Decodable` traits. Header can be any type that implements `Component` and `Header`. `Header` ensures that the required algorithm is available for signing and verification. `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, and `RS512` are supported. See the examples.

This library was originally forked from @mikkyang's rust-jwt.
