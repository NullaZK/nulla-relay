//! NULLA CLI library.

#![warn(missing_docs)]

#[cfg(feature = "cli")]
mod cli;
#[cfg(feature = "cli")]
mod command;
#[cfg(feature = "cli")]
mod error;

#[cfg(feature = "service")]
pub use polkadot_service::{
    self as service, Block, CoreApi, IdentifyVariant, ProvideRuntimeApi, TFullClient,
};

#[cfg(feature = "malus")]
pub use polkadot_service::overseer::validator_overseer_builder;

#[cfg(feature = "cli")]
pub use cli::*;

#[cfg(feature = "cli")]
pub use command::*;

#[cfg(feature = "cli")]
pub use sc_cli::{Error, Result};
