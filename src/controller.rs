use crypto::util::fixed_time_eq;
use digest::{Digest, FixedOutputReset};
use rand::{RngCore, rngs::{OsRng, ThreadRng, StdRng}, SeedableRng};

#[cfg(feature = "sha2")]
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

use crate::prefixed_api_key::PrefixedApiKey;

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
    pub fn finalize(self) -> Result<PrefixedApiKeyController<R, D>, &'static str> {
        if self.prefix.is_none() {
            return Err("Expected prefix to be set, but wasn't");
        }

        if self.rng.is_none() {
            return Err("Expected rng to be set, but wasn't");
        }

        if self.digest.is_none() {
            return Err("Expected digest to be set, but wasn't");
        }

        if self.short_token_length.is_none() {
            return Err("Expected short_token_length to be set, but wasn't");
        }

        if self.long_token_length.is_none() {
            return Err("Expected long_token_length to be set, but wasn't");
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
        self.short_token_length(8)
            .long_token_length(24)
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
        self.digest(Sha256::new())
            .rng_osrng()
            .default_lengths()
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
    use rand::RngCore;
    use rand::rngs::OsRng;

    use super::{ControllerBuilder, PrefixedApiKeyController};

    fn controller_generates_matching_hash<R, D>(mut controller: PrefixedApiKeyController<R, D>) -> bool
    where
        R: RngCore,
        D: Digest + FixedOutputReset
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
        assert!(
            controller_generates_matching_hash(controller_result.unwrap())
        );
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
        assert!(
            controller_generates_matching_hash(controller_result.unwrap())
        );
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
        assert!(
            controller_generates_matching_hash(controller_result.unwrap())
        );
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
        assert!(
            controller_generates_matching_hash(controller_result.unwrap())
        );
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
        assert!(
            controller_generates_matching_hash(controller_result.unwrap())
        );
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
        assert!(
            controller_generates_matching_hash(controller_result.unwrap())
        );
    }

    #[test]
    fn ok_with_seam_deafults() {
        let controller_result = ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .seam_defaults()
            .finalize();
        assert!(controller_result.is_ok());
        assert!(
            controller_generates_matching_hash(controller_result.unwrap())
        );
    }
}


#[derive(Debug)]
pub struct PrefixedApiKeyController<R: RngCore, D: Digest + FixedOutputReset> {
    prefix: String,
    rng: R,
    digest: D,
    short_token_prefix: Option<String>,
    short_token_length: usize,
    long_token_length: usize,
}

impl<R: RngCore, D: Digest + FixedOutputReset> PrefixedApiKeyController<R, D> {
    pub fn new(
        prefix: String,
        rng: R,
        digest: D,
        short_token_prefix: Option<String>,
        short_token_length: usize,
        long_token_length: usize,
    ) -> PrefixedApiKeyController<R, D> {
        PrefixedApiKeyController {
            prefix,
            rng,
            digest,
            short_token_prefix,
            short_token_length,
            long_token_length,
        }
    }

    /// Creates an instance of [ControllerBuilder] to enable building the
    /// controller via the builder pattern
    pub fn configure() -> ControllerBuilder<R, D> {
        ControllerBuilder::new()
    }

    /// Generates random bytes using the configured random number generator
    fn get_random_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut random_bytes = vec![0u8; length];
        // TODO: need to use try_fill_bytes to account for problems with the
        // underlying rng source. typically this will be fine, but the RngCore
        // docs say errors can arrise, and will cause a panic if you use fill_bytes
        self.rng.fill_bytes(&mut random_bytes);
        random_bytes
    }

    /// Generates a random token for part of the api key. This can be used for generating
    /// both the secret long key, and the shorter plaintext key. The random values are
    /// base58 encoded, which is a key feature/requirement of the library.
    fn get_random_token(&mut self, length: usize) -> String {
        let bytes = self.get_random_bytes(length);
        bs58::encode(bytes).into_string()
    }

    /// Generates a new PrefiexedApiKey using the configured string prefix, short token
    /// prefix (if configured), and random number generator. A hash of the new keys' long
    /// token is not calculated, so you'll still need to create the hash after calling
    /// this function.
    pub fn generate_key(&mut self) -> PrefixedApiKey {
        // generate the short token
        let mut short_token = self.get_random_token(self.short_token_length);

        // If the short token prefix is configured, concat it and the generated string and
        // drop any characters beyond the configured short token length
        if self.short_token_prefix.is_some() {
            let prefix_string = self.short_token_prefix.as_ref().unwrap().to_owned();
            short_token = (prefix_string + &short_token)
                .chars()
                .take(self.short_token_length)
                .collect()
        }

        // Generate the secret long token
        let long_token = self.get_random_token(self.long_token_length);

        // Construct and return the new pak
        PrefixedApiKey::new(self.prefix.to_owned(), short_token, long_token)
    }

    /// Generates a new key using the [generate_key](PrefixedApiKeyController::generate_key) function, but also calculates and
    /// returns the hash of the long token.
    pub fn generate_key_and_hash(&mut self) -> (PrefixedApiKey, String) {
        let pak = self.generate_key();
        let hash = self.long_token_hashed(&pak);
        (pak, hash)
    }

    /// Hashes the long token of the provided PrefixedApiKey using the hashing
    /// algorithm configured on the controller. The hashing instance gets
    /// reused each time this is called, which is why the [FixedOutputReset](digest::FixedOutputReset)
    /// trait is required.
    pub fn long_token_hashed(&mut self, pak: &PrefixedApiKey) -> String {
        pak.long_token_hashed(&mut self.digest)
    }

    /// Secure helper for checking if a given PrefixedApiKey matches a given
    /// long token hash. This uses the hashing algorithm configured on the controller
    /// and uses the [fixed_time_eq](crypto::util::fixed_time_eq) method of comparing hashes
    /// to avoid possible timing attacks.
    pub fn check_hash(&mut self, pak: &PrefixedApiKey, hash: String) -> bool {
        let pak_hash = self.long_token_hashed(pak);
        fixed_time_eq(pak_hash.as_bytes(), hash.as_bytes())
    }
}

#[cfg(test)]
mod controller_tests {
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    use crate::controller::PrefixedApiKeyController;
    use crate::PrefixedApiKey;

    #[test]
    fn configuration_works() {
        let controller = PrefixedApiKeyController::configure()
            .default_lengths()
            .prefix("mycompany".to_owned())
            .rng(OsRng)
            .digest(Sha256::new())
            .finalize();
        assert!(controller.is_ok())
    }

    #[test]
    fn generator() {
        let mut generator = PrefixedApiKeyController::new(
            "mycompany".to_owned(),
            OsRng,
            Sha256::new(),
            None,
            8,
            24,
        );
        let token_string = generator.generate_key().to_string();
        let pak_result = PrefixedApiKey::from_string(&token_string);
        assert_eq!(pak_result.is_ok(), true);
        let pak_string = pak_result.unwrap().to_string();
        assert_eq!(token_string, pak_string);
    }

    #[test]
    fn generator_short_token_prefix() {
        let short_length = 8;
        let short_prefix = "a".repeat(short_length);
        let mut generator = PrefixedApiKeyController::new(
            "mycompany".to_owned(),
            OsRng,
            Sha256::new(),
            Some(short_prefix.clone()),
            short_length,
            24,
        );
        let pak_short_token = generator.generate_key().short_token().to_owned();
        assert_eq!(pak_short_token, short_prefix);
    }

    #[test]
    fn generate_key_and_hash() {
        let mut generator = PrefixedApiKeyController::new(
            "mycompany".to_owned(),
            OsRng,
            Sha256::new(),
            None,
            8,
            24,
        );
        let (pak, hash) = generator.generate_key_and_hash();
        assert!(generator.check_hash(&pak, hash))
    }

    #[test]
    fn check_long_token_via_generator() {
        let pak_string = "mycompany_CEUsS4psCmc_BddpcwWyCT3EkDjHSSTRaSK1dxtuQgbjb";
        let hash = "0f01ab6e0833f280b73b2b618c16102d91c0b7c585d42a080d6e6603239a8bee";

        let pak: PrefixedApiKey = pak_string.try_into().unwrap();

        let mut generator = PrefixedApiKeyController::new(
            "mycompany".to_owned(),
            OsRng,
            Sha256::new(),
            None,
            8,
            24
        );

        assert_eq!(generator.long_token_hashed(&pak), hash);
    }

    #[test]
    fn generator_digest_resets_after_hashing() {
        let pak1_string = "mycompany_CEUsS4psCmc_BddpcwWyCT3EkDjHSSTRaSK1dxtuQgbjb";
        let pak1_hash = "0f01ab6e0833f280b73b2b618c16102d91c0b7c585d42a080d6e6603239a8bee";
        let pak1: PrefixedApiKey = pak1_string.try_into().unwrap();

        let pak2_string = "mycompany_CEUsS4psCmc_BddpcwWyCT3EkDjHSSTRaSK1dxtuQgbjb";
        let pak2_hash = "0f01ab6e0833f280b73b2b618c16102d91c0b7c585d42a080d6e6603239a8bee";
        let pak2: PrefixedApiKey = pak2_string.try_into().unwrap();

        let mut generator = PrefixedApiKeyController::new(
            "mycompany".to_owned(),
            OsRng,
            Sha256::new(),
            None,
            8,
            24,
        );

        assert_eq!(generator.long_token_hashed(&pak1), pak1_hash);
        assert_eq!(generator.long_token_hashed(&pak2), pak2_hash);
    }

    #[test]
    fn generator_matches_hash() {
        let pak_string = "mycompany_CEUsS4psCmc_BddpcwWyCT3EkDjHSSTRaSK1dxtuQgbjb";
        let pak_hash = "0f01ab6e0833f280b73b2b618c16102d91c0b7c585d42a080d6e6603239a8bee";
        let pak: PrefixedApiKey = pak_string.try_into().unwrap();

        let mut generator = PrefixedApiKeyController::new(
            "mycompany".to_owned(),
            OsRng,
            Sha256::new(),
            None,
            8,
            24,
        );

        assert!(generator.check_hash(&pak, pak_hash.to_string()));
    }
}
