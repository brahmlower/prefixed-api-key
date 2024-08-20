use crate::PrefixedApiKeyController;

use rand::rngs::{OsRng, StdRng, ThreadRng};

// Aliases using OsRng
#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

#[cfg(feature = "sha2")]
pub type PakControllerOsSha224 = PrefixedApiKeyController<OsRng, Sha224>;

#[cfg(feature = "sha2")]
pub type PakControllerOsSha256 = PrefixedApiKeyController<OsRng, Sha256>;

#[cfg(feature = "sha2")]
pub type PakControllerOsSha384 = PrefixedApiKeyController<OsRng, Sha384>;

#[cfg(feature = "sha2")]
pub type PakControllerOsSha512 = PrefixedApiKeyController<OsRng, Sha512>;

#[cfg(feature = "sha2")]
pub type PakControllerOsSha512_224 = PrefixedApiKeyController<OsRng, Sha512_224>;

#[cfg(feature = "sha2")]
pub type PakControllerOsSha512_256 = PrefixedApiKeyController<OsRng, Sha512_256>;

// Aliases using StdRng
#[cfg(feature = "sha2")]
pub type PakControllerStdSha224 = PrefixedApiKeyController<StdRng, Sha224>;

#[cfg(feature = "sha2")]
pub type PakControllerStdSha256 = PrefixedApiKeyController<StdRng, Sha256>;

#[cfg(feature = "sha2")]
pub type PakControllerStdSha384 = PrefixedApiKeyController<StdRng, Sha384>;

#[cfg(feature = "sha2")]
pub type PakControllerStdSha512 = PrefixedApiKeyController<StdRng, Sha512>;

#[cfg(feature = "sha2")]
pub type PakControllerStdSha512_224 = PrefixedApiKeyController<StdRng, Sha512_224>;

#[cfg(feature = "sha2")]
pub type PakControllerStdSha512_256 = PrefixedApiKeyController<StdRng, Sha512_256>;

// Aliases using ThreadRng
#[cfg(feature = "sha2")]
pub type PakControllerThreadSha224 = PrefixedApiKeyController<ThreadRng, Sha224>;

#[cfg(feature = "sha2")]
pub type PakControllerThreadSha256 = PrefixedApiKeyController<ThreadRng, Sha256>;

#[cfg(feature = "sha2")]
pub type PakControllerThreadSha384 = PrefixedApiKeyController<ThreadRng, Sha384>;

#[cfg(feature = "sha2")]
pub type PakControllerThreadSha512 = PrefixedApiKeyController<ThreadRng, Sha512>;

#[cfg(feature = "sha2")]
pub type PakControllerThreadSha512_224 = PrefixedApiKeyController<ThreadRng, Sha512_224>;

#[cfg(feature = "sha2")]
pub type PakControllerThreadSha512_256 = PrefixedApiKeyController<ThreadRng, Sha512_256>;
