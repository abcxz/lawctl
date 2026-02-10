//! Lawctl — Universal Agent Firewall library.
//!
//! This library exposes the core components of Lawctl for integration testing
//! and programmatic use. The binary entrypoint is in `main.rs`.

// Many items are pub for use by the shim binary and integration tests,
// which are separate compilation units — suppress false dead_code warnings.
#![allow(dead_code)]

pub mod approval;
pub mod audit;
pub mod cli;
pub mod gateway;
pub mod policy;
pub mod sandbox;
pub mod utils;
