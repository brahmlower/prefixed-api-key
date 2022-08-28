use rand::RngCore;
use digest::Digest;
use std::{error::Error, fmt};

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
pub struct PrefixedApiKeyGenerator<'a, R: RngCore> {
    prefix: String,
    rng_source: &'a mut R,
    options: GeneratorOptions,
}

impl<'a, R: RngCore> PrefixedApiKeyGenerator<'a, R> {
    pub fn new(prefix: String, rng_source: &'a mut R, options: GeneratorOptions) -> PrefixedApiKeyGenerator<R> {
        PrefixedApiKeyGenerator { prefix, rng_source, options }
    }

    fn get_random_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut random_bytes = vec![0u8; length];
        // TODO: need to use try_fill_bytes to account for problems with the
        // underlying rng source. typically this will be fine, but the RngCore
        // docs say errors can arrise, and will cause a panic if you use fill_bytes
        self.rng_source.fill_bytes(&mut random_bytes);
        random_bytes
    }

    fn generate_token(&mut self, length: usize) -> String {
        let bytes = self.get_random_bytes(length);
        bs58::encode(bytes).into_string()
    }

    pub fn new_key(&mut self) -> PrefixedApiKey {
        let mut short_token = self.generate_token(self.options.short_token_length);
        if self.options.short_token_prefix.is_some() {
            let prefix_string = self.options.short_token_prefix.as_ref().unwrap().to_owned();
            short_token = (prefix_string + &short_token)
                .chars()
                .take(self.options.short_token_length)
                .collect()
        }
        let long_token = self.generate_token(self.options.long_token_length);
        PrefixedApiKey::new(self.prefix.to_owned(), short_token, long_token)
    }
}

#[derive(Debug, PartialEq)]
pub enum PrefixedApiKeyError {
    WrongNumberOfParts(usize),
}

impl Error for PrefixedApiKeyError {}

impl fmt::Display for PrefixedApiKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(Debug)]
pub struct PrefixedApiKey {
    prefix: String,
    short_token: String,
    long_token: String,
}

impl PrefixedApiKey {
    pub fn new(prefix: String, short_token: String, long_token: String) -> PrefixedApiKey {
        PrefixedApiKey {
            prefix,
            short_token,
            long_token,
        }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn short_token(&self) -> &str {
        &self.short_token
    }

    pub fn long_token(&self) -> &str {
        &self.long_token
    }

    /// Hashes the long token using the provided hashing algorithm
    pub fn long_token_hashed<H: Digest>(&self, mut hasher: H) -> String {
        hasher.update(self.long_token.clone());
        hex::encode(hasher.finalize())
    }

    pub fn from_string(pak_string: &str) -> Result<PrefixedApiKey, PrefixedApiKeyError> {
        let parts: Vec<&str> = pak_string.split("_").collect();

        if parts.len() != 3 {
            // Incorrect number of parts
            return Err(PrefixedApiKeyError::WrongNumberOfParts(parts.len()));
        }

        Ok(PrefixedApiKey::new(
            parts[0].to_owned(),
            parts[1].to_owned(),
            parts[2].to_owned(),
        ))
    }

    pub fn as_string(&self) -> String {
        format!("{}_{}_{}", self.prefix, self.short_token, self.long_token)
    }
}

impl TryInto<PrefixedApiKey> for &str {
    type Error = PrefixedApiKeyError;

    fn try_into(self) -> Result<PrefixedApiKey, Self::Error> {
        PrefixedApiKey::from_string(self)
    }
}

impl fmt::Display for PrefixedApiKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Displays the key without showing the secret long token
        write!(f, "{}_{}_***", self.prefix(), self.short_token())
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use rand::rngs::OsRng;

    use crate::{GeneratorOptions, PrefixedApiKey, PrefixedApiKeyError, PrefixedApiKeyGenerator};

    #[test]
    fn as_string_is_expected() {
        let prefix = "mycompany".to_owned();
        let short = "abcdefg".to_owned();
        let long = "bacdegadsa".to_owned();
        let expected_token = format!("{}_{}_{}", prefix, short, long);
        let pak = PrefixedApiKey::new(prefix, short, long);
        assert_eq!(pak.as_string(), expected_token)
    }

    #[test]
    fn self_from_string_works() {
        let pak_string = "mycompany_abcdefg_bacdegadsa";
        let pak_result = PrefixedApiKey::from_string(pak_string);
        assert_eq!(pak_result.is_ok(), true);
        assert_eq!(pak_result.unwrap().as_string(), pak_string);
    }

    #[test]
    fn str_into_pak() {
        let pak_string = "mycompany_abcdefg_bacdegadsa";
        let pak_result: Result<PrefixedApiKey, _> = pak_string.try_into();
        assert_eq!(pak_result.is_ok(), true);
        assert_eq!(pak_result.unwrap().as_string(), pak_string);
    }

    #[test]
    fn string_into_pak_via_as_ref() {
        let pak_string = "mycompany_abcdefg_bacdegadsa".to_owned();
        let pak_result: Result<PrefixedApiKey, _> = pak_string.as_str().try_into();
        assert_eq!(pak_result.is_ok(), true);
        assert_eq!(pak_result.unwrap().as_string(), pak_string);
    }

    #[test]
    fn str_into_pak_with_extra_parts() {
        let pak_string = "mycompany_abcd_efg_bacdegadsa";
        let pak_result: Result<PrefixedApiKey, _> = pak_string.try_into();
        assert_eq!(pak_result.is_err(), true);
        assert_eq!(
            pak_result.unwrap_err(),
            PrefixedApiKeyError::WrongNumberOfParts(4)
        );
    }

    #[test]
    fn check_long_token() {
        let pak_string = "mycompany_CEUsS4psCmc_BddpcwWyCT3EkDjHSSTRaSK1dxtuQgbjb";
        let hash = "0f01ab6e0833f280b73b2b618c16102d91c0b7c585d42a080d6e6603239a8bee";

        let pak: PrefixedApiKey = pak_string.try_into().unwrap();
        let hasher = Sha256::new();
        assert_eq!(pak.long_token_hashed(hasher), hash);
    }

    #[test]
    fn generator() {
        let prefix = "mycompany".to_owned();
        let mut rng_source = OsRng;
        let gen_options = GeneratorOptions::default();
        let mut generator = PrefixedApiKeyGenerator::new(prefix, &mut rng_source, gen_options);
        let token_string = generator.new_key().as_string();
        let new_inst = PrefixedApiKey::from_string(&token_string);
        assert_eq!(new_inst.is_ok(), true);
        let new_string = new_inst.unwrap().as_string();
        assert_eq!(token_string, new_string);
    }

    #[test]
    fn generator_short_token_prefix() {
        let short_length = 8;
        let short_prefix = "a".repeat(short_length);
        let gen_options = GeneratorOptions::default()
            .short_token_length(short_length)
            .short_token_prefix(Some(short_prefix.clone()));
        let prefix = "mycompany".to_owned();
        let mut rng_source = OsRng;
        let mut generator = PrefixedApiKeyGenerator::new(prefix, &mut rng_source, gen_options);
        let pak_short_token = generator.new_key().short_token().to_owned();
        assert_eq!(pak_short_token, short_prefix);
    }
}
