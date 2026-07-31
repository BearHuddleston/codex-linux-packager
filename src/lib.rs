#![forbid(unsafe_code)]

//! Auditable packaging and validation primitives for Linux x86_64.

pub mod appdir;
pub mod appimage;
pub mod archive;
pub mod asar;
pub mod cli;
pub mod contract_refresh;
pub mod download;
pub mod error;
pub mod extract;
pub mod feed;
pub mod manifest;
pub mod native;
pub mod process;
pub mod release;
pub mod release_evidence;
pub mod runtime;
pub mod signature;
pub mod staging;
pub mod update;
pub mod updater;
pub mod upstream;
