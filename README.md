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

The library provides a `Token` type that wraps a header and claims. The claims can be any type that implements the `Component` trait, which is automatically implemented for types that implement the `Sized`, and must have the attribute `#[derive(Serialize, Deserialize)`. Header can be any type that implements `Component` and `Header`. `Header` ensures that the required algorithm is available for signing and verification. `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, and `RS512` are supported. See the examples.

This library was originally forked from @mikkyang's rust-jwt.
