use digest::{Digest, FixedOutputReset};
use rand::{
    rngs::{OsRng, StdRng, ThreadRng},
    RngCore, SeedableRng,
};
use std::error::Error;
use std::fmt;

#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

use crate::controller::PrefixedApiKeyController;

#[derive(Debug, Clone)]
pub enum BuilderError {
    MissingPrefix,
    MissingRng,
    MissingDigest,
    MissingShortTokenLength,
    MissingLongTokenLength,
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BuilderError::MissingPrefix => write!(f, "expected prefix to be set, but wasn't"),
            BuilderError::MissingRng => write!(f, "expected rng to be set, but wasn't"),
            BuilderError::MissingDigest => write!(f, "expected digest to be set, but wasn't"),
            BuilderError::MissingShortTokenLength => {
                write!(f, "expected short_token_length to be set, but wasn't")
            }
            BuilderError::MissingLongTokenLength => {
                write!(f, "expected long_token_length to be set, but wasn't")
            }
        }
    }
}

impl Error for BuilderError {}

pub struct ControllerBuilder<R: RngCore, D: Digest + FixedOutputReset> {
    prefix: Option<String>,
    rng: Option<R>,
    digest: Option<D>,
    short_token_prefix: Option<String>,
    short_token_length: Option<usize>,
    long_token_length: Option<usize>,
}

impl<R: RngCore, D: Digest + FixedOutputReset> ControllerBuilder<R, D> {
    pub fn new() -> ControllerBuilder<R, D> {
        ControllerBuilder {
            prefix: None,
            rng: None,
            digest: None,
            short_token_prefix: None,
            short_token_length: None,
            long_token_length: None,
        }
    }

    /// Finishes building the controller, returning Err if any necessary configs are
    /// missing.
    pub fn finalize(self) -> Result<PrefixedApiKeyController<R, D>, BuilderError> {
        if self.prefix.is_none() {
            return Err(BuilderError::MissingPrefix);
        }

        if self.rng.is_none() {
            return Err(BuilderError::MissingRng);
        }

        if self.digest.is_none() {
            return Err(BuilderError::MissingDigest);
        }

        if self.short_token_length.is_none() {
            return Err(BuilderError::MissingShortTokenLength);
        }

        if self.long_token_length.is_none() {
            return Err(BuilderError::MissingLongTokenLength);
        }

        Ok(PrefixedApiKeyController::new(
            self.prefix.unwrap(),
            self.rng.unwrap(),
            self.digest.unwrap(),
            self.short_token_prefix,
            self.short_token_length.unwrap(),
            self.long_token_length.unwrap(),
        ))
    }

    /// Helper for setting the default short and long token length based on the
    /// defaults set in the [typescript version Prefixed API Key module](https://github.com/seamapi/prefixed-api-key/blob/main/src/index.ts#L19-L20).
    pub fn default_lengths(self) -> Self {
        self.short_token_length(8).long_token_length(24)
    }

    /// Sets the token prefix. This should be the name of your company or organization.
    pub fn prefix(mut self, prefix: String) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// An instance of a struct that implements RngCore, which will be used for
    /// generating bytes used in the short and long tokens of the key.
    pub fn rng(mut self, rng: R) -> Self {
        self.rng = Some(rng);
        self
    }

    /// An instance of a struct that implements Digest, which will be used for
    /// hashing the secret token of new keys.
    pub fn digest(mut self, digest: D) -> Self {
        self.digest = Some(digest);
        self
    }

    /// An optional prefix for the short tokens. The length of this value should
    /// be less than the value you set for the `short_token_length`, and should
    /// leave enough space to avoid collisions with other short tokens.
    ///
    /// Default: None
    pub fn short_token_prefix(mut self, short_token_prefix: Option<String>) -> Self {
        self.short_token_prefix = short_token_prefix;
        self
    }

    /// The length of the short token
    pub fn short_token_length(mut self, short_token_length: usize) -> Self {
        self.short_token_length = Some(short_token_length);
        self
    }

    /// The length of the secret long token
    pub fn long_token_length(mut self, long_token_length: usize) -> Self {
        self.long_token_length = Some(long_token_length);
        self
    }
}

impl<D: Digest + FixedOutputReset> ControllerBuilder<OsRng, D> {
    /// Helper function for configuring the Controller with an instance of [OsRng](rand::rngs::OsRng).
    ///
    /// <p style="background:rgba(255,181,77,0.16);padding:0.75em;">
    /// <strong>Warning:</strong>
    /// The RNG you pick is an important decision. Please familiarize yourself with the
    /// <a href="https://docs.rs/rand/latest/rand/rngs/index.html#background-random-number-generators-rngs">types of RNGs</a>,
    /// and then read the descriptions of each of
    /// <a href="https://docs.rs/rand/latest/rand/rngs/index.html#our-generators">the RNGs provided in the rand crate</a>
    /// to determine the most appropriate RNG for your use case.
    /// </p>
    pub fn rng_osrng(self) -> Self {
        self.rng(OsRng)
    }
}

impl<D: Digest + FixedOutputReset> ControllerBuilder<ThreadRng, D> {
    /// Helper function for configuring the Controller with an instance of [ThreadRng](rand::rngs::ThreadRng) created
    /// by calling [default](rand::rngs::ThreadRng::default).
    ///
    /// <p style="background:rgba(255,181,77,0.16);padding:0.75em;">
    /// <strong>Warning:</strong>
    /// The RNG you pick is an important decision. Please familiarize yourself with the
    /// <a href="https://docs.rs/rand/latest/rand/rngs/index.html#background-random-number-generators-rngs">types of RNGs</a>,
    /// and then read the descriptions of each of
    /// <a href="https://docs.rs/rand/latest/rand/rngs/index.html#our-generators">the RNGs provided in the rand crate</a>
    /// to determine the most appropriate RNG for your use case.
    /// </p>
    pub fn rng_threadrng(self) -> Self {
        self.rng(ThreadRng::default())
    }
}

impl<D: Digest + FixedOutputReset> ControllerBuilder<StdRng, D> {
    /// Helper function for configuring the Controller with an instance of [StdRng](rand::rngs::StdRng) created
    /// by calling [from_entropy](rand::rngs::StdRng::from_entropy).
    ///
    /// <p style="background:rgba(255,181,77,0.16);padding:0.75em;">
    /// <strong>Warning:</strong>
    /// The RNG you pick is an important decision. Please familiarize yourself with the
    /// <a href="https://docs.rs/rand/latest/rand/rngs/index.html#background-random-number-generators-rngs">types of RNGs</a>,
    /// and then read the descriptions of each of
    /// <a href="https://docs.rs/rand/latest/rand/rngs/index.html#our-generators">the RNGs provided in the rand crate</a>
    /// to determine the most appropriate RNG for your use case.
    /// </p>
    pub fn rng_stdrng(self) -> Self {
        self.rng(StdRng::from_entropy())
    }
}

#[cfg(feature = "sha2")]
impl<R: RngCore> ControllerBuilder<R, Sha224> {
    /// Helper function for configuring the Controller with a new [Sha224](sha2::Sha224) instance
    ///
    /// Requires the "sha2" feature
    pub fn digest_sha224(self) -> Self {
        self.digest(Sha224::new())
    }
}

#[cfg(feature = "sha2")]
impl ControllerBuilder<OsRng, Sha256> {
    /// Helper function for configuring the Controller with a new [Sha256](sha2::Sha256) instance
    ///
    /// Requires the "sha2" feature
    pub fn seam_defaults(self) -> Self {
        self.digest(Sha256::new()).rng_osrng().default_lengths()
    }
}

#[cfg(feature = "sha2")]
impl<R: RngCore> ControllerBuilder<R, Sha256> {
    /// Helper function for configuring the Controller with a new [Sha256](sha2::Sha256) instance
    ///
    /// Requires the "sha2" feature
    pub fn digest_sha256(self) -> Self {
        self.digest(Sha256::new())
    }
}

#[cfg(feature = "sha2")]
impl<R: RngCore> ControllerBuilder<R, Sha384> {
    /// Helper function for configuring the Controller with a new [Sha384](sha2::Sha384) instance
    ///
    /// Requires the "sha2" feature
    pub fn digest_sha384(self) -> Self {
        self.digest(Sha384::new())
    }
}

#[cfg(feature = "sha2")]
impl<R: RngCore> ControllerBuilder<R, Sha512> {
    /// Helper function for configuring the Controller with a new [Sha512](sha2::Sha512) instance
    ///
    /// Requires the "sha2" feature
    pub fn digest_sha512(self) -> Self {
        self.digest(Sha512::new())
    }
}

#[cfg(feature = "sha2")]
impl<R: RngCore> ControllerBuilder<R, Sha512_224> {
    /// Helper function for configuring the Controller with a new [Sha512_224](sha2::Sha512_224) instance
    ///
    /// Requires the "sha2" feature
    pub fn digest_sha512_224(self) -> Self {
        self.digest(Sha512_224::new())
    }
}

#[cfg(feature = "sha2")]
impl<R: RngCore> ControllerBuilder<R, Sha512_256> {
    /// Helper function for configuring the Controller with a new [Sha512_256](sha2::Sha512_256) instance
    ///
    /// Requires the "sha2" feature
    pub fn digest_sha512_256(self) -> Self {
        self.digest(Sha512_256::new())
    }
}

impl<R: RngCore, D: Digest + FixedOutputReset> Default for ControllerBuilder<R, D> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod controller_builder_tests {
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    use super::ControllerBuilder;

    #[test]
    fn errors_when_no_values_set() {
        let controller_result = ControllerBuilder::<OsRng, Sha256>::new().finalize();
        assert!(controller_result.is_err())
    }

    #[test]
    fn ok_with_all_values_provided() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest(Sha256::new())
            .short_token_prefix(None)
            .short_token_length(4)
            .long_token_length(500)
            .finalize();
        assert!(controller_result.is_ok())
    }

    #[test]
    fn ok_with_default_short_token_prefix() {
        // We just omit setting the short_token_prefix to use the default None value
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest(Sha256::new())
            .short_token_length(4)
            .long_token_length(500)
            .finalize();
        assert!(controller_result.is_ok())
    }

    #[test]
    fn ok_with_default_lengths() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest(Sha256::new())
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok())
    }

    #[test]
    fn ok_with_rng_osrng() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng_osrng()
            .digest(Sha256::new())
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok())
    }

    #[test]
    fn ok_with_rng_threadrng() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng_threadrng()
            .digest(Sha256::new())
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok())
    }

    #[test]
    fn ok_with_rng_stdrng() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng_stdrng()
            .digest(Sha256::new())
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok())
    }
}

#[cfg(feature = "sha2")]
#[cfg(test)]
mod controller_builder_sha2_tests {
    use digest::{Digest, FixedOutputReset};
    use rand::rngs::OsRng;
    use rand::RngCore;

    use super::{ControllerBuilder, PrefixedApiKeyController};

    fn controller_generates_matching_hash<R, D>(
        mut controller: PrefixedApiKeyController<R, D>,
    ) -> bool
    where
        R: RngCore,
        D: Digest + FixedOutputReset,
    {
        let (pak, hash) = controller.generate_key_and_hash();
        controller.check_hash(&pak, hash)
    }

    #[test]
    fn ok_with_digest_sha224() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest_sha256()
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok());
        assert!(controller_generates_matching_hash(
            controller_result.unwrap()
        ));
    }

    #[test]
    fn ok_with_digest_sha256() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest_sha256()
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok());
        assert!(controller_generates_matching_hash(
            controller_result.unwrap()
        ));
    }

    #[test]
    fn ok_with_digest_sha384() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest_sha384()
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok());
        assert!(controller_generates_matching_hash(
            controller_result.unwrap()
        ));
    }

    #[test]
    fn ok_with_digest_sha512() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest_sha512()
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok());
        assert!(controller_generates_matching_hash(
            controller_result.unwrap()
        ));
    }

    #[test]
    fn ok_with_digest_sha512_224() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest_sha512_224()
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok());
        assert!(controller_generates_matching_hash(
            controller_result.unwrap()
        ));
    }

    #[test]
    fn ok_with_digest_sha512_256() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest_sha512_256()
            .short_token_prefix(None)
            .default_lengths()
            .finalize();
        assert!(controller_result.is_ok());
        assert!(controller_generates_matching_hash(
            controller_result.unwrap()
        ));
    }

    #[test]
    fn ok_with_seam_deafults() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .seam_defaults()
            .finalize();
        assert!(controller_result.is_ok());
        assert!(controller_generates_matching_hash(
            controller_result.unwrap()
        ));
    }
}
