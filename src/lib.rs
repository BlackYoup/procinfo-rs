#![recursion_limit = "1000"]
#![cfg_attr(rustc_nightly, feature(test))]

#![allow(dead_code)] // TODO: remove

#[macro_use]
extern crate nom;

extern crate byteorder;
extern crate libc;
extern crate time;

#[macro_use]
mod parsers;

mod loadavg;
pub mod pid;

pub use loadavg::{LoadAvg, loadavg};
