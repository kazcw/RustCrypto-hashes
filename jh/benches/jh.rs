#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate jh;

bench!(jh::Jh256);
