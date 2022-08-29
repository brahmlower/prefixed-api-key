use crypto::util::fixed_time_eq;
use digest::{Digest, FixedOutputReset};
use rand::RngCore;

use crate::prefixed_api_key::PrefixedApiKey;

#[derive(Debug)]
pub struct GeneratorOptions {
    short_token_prefix: Option<String>,
    short_token_length: usize,
    long_token_length: usize,
}

impl GeneratorOptions {
    pub fn short_token_prefix(mut self, value: Option<String>) -> Self {
        self.short_token_prefix = value;
        self
    }

    pub fn short_token_length(mut self, value: usize) -> Self {
        self.short_token_length = value;
        self
    }

    pub fn long_token_length(mut self, value: usize) -> Self {
        self.short_token_length = value;
        self
    }
}

impl Default for GeneratorOptions {
    fn default() -> GeneratorOptions {
        GeneratorOptions {
            short_token_prefix: None,
            short_token_length: 8,
            long_token_length: 24,
        }
    }
}

#[derive(Debug)]
pub struct PrefixedApiKeyController<R: RngCore, H: Digest + FixedOutputReset> {
    prefix: String,
    rng_source: R,
    hasher: H,
    options: GeneratorOptions,
}

impl<R: RngCore, H: Digest + FixedOutputReset> PrefixedApiKeyController<R, H> {
    pub fn new(
        prefix: String,
        rng_source: R,
        hasher: H,
        options: GeneratorOptions,
    ) -> PrefixedApiKeyController<R, H> {
        PrefixedApiKeyController {
            prefix,
            rng_source,
            hasher,
            options,
        }
    }

    /// Generates random bytes using the configured random number generator
    fn get_random_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut random_bytes = vec![0u8; length];
        // TODO: need to use try_fill_bytes to account for problems with the
        // underlying rng source. typically this will be fine, but the RngCore
        // docs say errors can arrise, and will cause a panic if you use fill_bytes
        self.rng_source.fill_bytes(&mut random_bytes);
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
        let mut short_token = self.get_random_token(self.options.short_token_length);

        // If the short token prefix is configured, concat it and the generated string and
        // drop any characters beyond the configured short token length
        if self.options.short_token_prefix.is_some() {
            let prefix_string = self.options.short_token_prefix.as_ref().unwrap().to_owned();
            short_token = (prefix_string + &short_token)
                .chars()
                .take(self.options.short_token_length)
                .collect()
        }

        // Generate the secret long token
        let long_token = self.get_random_token(self.options.long_token_length);

        // Construct and return the new pak
        PrefixedApiKey::new(self.prefix.to_owned(), short_token, long_token)
    }

    // Generates a new key using the `generate_key` function, but also calculates and
    // returns the hash of the long token.
    pub fn generate_key_and_hash(&mut self) -> (PrefixedApiKey, String) {
        let pak = self.generate_key();
        let hash = self.long_token_hashed(&pak);
        (pak, hash)
    }

    /// Hashes the long token of the provided PrefixedApiKey using the hashing
    /// algorithm configured on the controller. The hashing instance gets
    /// reused each time this is called, which is why the `FixedOutputReset`
    /// trait is required.
    pub fn long_token_hashed(&mut self, pak: &PrefixedApiKey) -> String {
        pak.long_token_hashed(&mut self.hasher)
    }

    /// Secure helper for checking if a given PrefixedApiKey matches a given
    /// long token hash. This uses the hashing algorithm configured on the controller
    /// and uses the `crypto::util::fixed_time_eq` method of comparing hashes
    /// to avoid possible timing attacks.
    pub fn check_hash(&mut self, pak: &PrefixedApiKey, hash: String) -> bool {
        let pak_hash = self.long_token_hashed(pak);
        fixed_time_eq(pak_hash.as_bytes(), hash.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    use crate::controller::{GeneratorOptions, PrefixedApiKeyController};
    use crate::PrefixedApiKey;

    #[test]
    fn generator() {
        let prefix = "mycompany".to_owned();
        let gen_options = GeneratorOptions::default();
        let mut generator =
            PrefixedApiKeyController::new(prefix, OsRng, Sha256::new(), gen_options);
        let token_string = generator.generate_key().to_string();
        let new_inst = PrefixedApiKey::from_string(&token_string);
        assert_eq!(new_inst.is_ok(), true);
        let new_string = new_inst.unwrap().to_string();
        assert_eq!(token_string, new_string);
    }

    #[test]
    fn generator_short_token_prefix() {
        let short_length = 8;
        let short_prefix = "a".repeat(short_length);
        let gen_options = GeneratorOptions::default()
            .short_token_length(short_length)
            .short_token_prefix(Some(short_prefix.clone()));
        let mut generator = PrefixedApiKeyController::new(
            "mycompany".to_owned(),
            OsRng,
            Sha256::new(),
            gen_options,
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
            GeneratorOptions::default(),
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
            GeneratorOptions::default(),
        );

        assert_eq!(generator.long_token_hashed(&pak), hash);
    }

    #[test]
    fn generator_hasher_resets_after_hashing() {
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
            GeneratorOptions::default(),
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
            GeneratorOptions::default(),
        );

        assert!(generator.check_hash(&pak, pak_hash.to_string()));
    }
}
