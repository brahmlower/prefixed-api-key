mod prefixed_api_key;
pub use crate::prefixed_api_key::PrefixedApiKey;
pub use crate::prefixed_api_key::PrefixedApiKeyError;

mod controller_builder;
pub use crate::controller_builder::BuilderError;
pub use crate::controller_builder::ControllerBuilder;

mod controller;
pub use crate::controller::PrefixedApiKeyController;

mod controller_alias;
pub use controller_alias::*;

// reexport rngs
pub use rand;

// rexport digests
#[cfg(feature = "sha2")]
pub use sha2;

#[doc = include_str!("../README.md")]
#[cfg(feature = "sha2")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
