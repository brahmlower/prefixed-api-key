mod prefixed_api_key;
pub use crate::prefixed_api_key::PrefixedApiKey;
pub use crate::prefixed_api_key::PrefixedApiKeyError;

mod controller_builder;
pub use crate::controller_builder::BuilderError;
pub use crate::controller_builder::ControllerBuilder;

mod controller;
pub use crate::controller::PrefixedApiKeyController;

// reexport rngs
pub use rand;

// rexport digests
#[cfg(feature = "sha2")]
pub use sha2;

#[doc = include_str!("../readme.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
