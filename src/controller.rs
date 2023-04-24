use constant_time_eq::constant_time_eq;
use digest::{Digest, FixedOutputReset};
use rand::RngCore;

use crate::controller_builder::ControllerBuilder;
use crate::prefixed_api_key::PrefixedApiKey;

#[derive(Debug)]
pub struct PrefixedApiKeyController<R: RngCore, D: Digest + FixedOutputReset> {
    prefix: String,
    rng: R,
    digest: D,
    short_token_prefix: Option<String>,
    short_token_length: usize,
    long_token_length: usize,
}

impl<R: RngCore, D: Digest + FixedOutputReset + Clone> PrefixedApiKeyController<R, D> {
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
    pub fn long_token_hashed(&self, pak: &PrefixedApiKey) -> String {
        let mut digest = self.digest.clone();
        pak.long_token_hashed(&mut digest)
    }

    /// Secure helper for checking if a given PrefixedApiKey matches a given
    /// long token hash. This uses the hashing algorithm configured on the controller
    /// and uses the [constant_time_eq](constant_time_eq::constant_time_eq) method of comparing hashes
    /// to avoid possible timing attacks.
    pub fn check_hash(&self, pak: &PrefixedApiKey, hash: &str) -> bool {
        let pak_hash = self.long_token_hashed(pak);
        constant_time_eq(pak_hash.as_bytes(), hash.as_bytes())
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
        assert!(generator.check_hash(&pak, &hash))
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
            24,
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

        assert!(generator.check_hash(&pak, pak_hash));
    }
}
