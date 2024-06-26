use digest::{Digest, FixedOutputReset};
use std::error::Error;
use std::fmt;
use std::fmt::Debug;

#[derive(Debug, PartialEq, Eq)]
pub enum PrefixedApiKeyError {
    WrongNumberOfParts(usize),
}

impl Error for PrefixedApiKeyError {}

impl fmt::Display for PrefixedApiKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: Display should use something other than debug display
        write!(f, "{:?}", self)
    }
}

/// A struct representing the api token generated for, and provided to,
/// the user. An instance of this struct can be instantiated from a string
/// provided by the user for further validation, or it can be instantiated
/// via the `new` method while generating a new key to be given to the user.
pub struct PrefixedApiKey {
    prefix: String,
    short_token: String,
    long_token: String,
}

impl PrefixedApiKey {
    /// Constructs a new instance of the struct. This is just a wrapper around
    /// directly instantiating the struct, and makes no assertions or assumptions
    /// about the values provided.
    pub fn new(prefix: String, short_token: String, long_token: String) -> PrefixedApiKey {
        PrefixedApiKey {
            prefix,
            short_token,
            long_token,
        }
    }

    /// Getter method for accessing the key's prefix
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Getter method for accessing the key's short token
    pub fn short_token(&self) -> &str {
        &self.short_token
    }

    /// Getter method for accessing the key's secret long token
    pub fn long_token(&self) -> &str {
        &self.long_token
    }

    /// Gets the hashed form of the keys secret long token, using the hashing
    /// algorithm provided as `digest`. This resets the digest instance while
    /// finalizing so it may be reused afterward.
    pub fn long_token_hashed<D: Digest + FixedOutputReset>(&self, digest: &mut D) -> String {
        Digest::update(digest, self.long_token.clone());
        hex::encode(digest.finalize_reset())
    }

    /// Instantiates the struct from the string form of the api token. This
    /// validates that the string has the expected number of parts (deliniated by `"_"`),
    /// but otherwise makes no assertions or assumptions about the values.
    pub fn from_string(pak_string: &str) -> Result<PrefixedApiKey, PrefixedApiKeyError> {
        let parts: Vec<&str> = pak_string.split('_').collect();

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
}

/// A custom implementation of Debug that masks the secret long token that way
/// the struct can be debug printed without leaking sensitive info into logs
impl Debug for PrefixedApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrefixedApiKey")
            .field("prefix", &self.prefix)
            .field("short_token", &self.short_token)
            .field("long_token", &"***")
            .finish()
    }
}

/// A manual implementation of `ToString` which does not mask the secret long token.
/// The `Display` trait is explicitely not implemented to avoid accidentally leaking
/// the long token in logs.
#[allow(clippy::to_string_trait_impl)]
impl ToString for PrefixedApiKey {
    fn to_string(&self) -> String {
        format!("{}_{}_{}", self.prefix, self.short_token, self.long_token)
    }
}

impl TryInto<PrefixedApiKey> for &str {
    type Error = PrefixedApiKeyError;

    fn try_into(self) -> Result<PrefixedApiKey, Self::Error> {
        PrefixedApiKey::from_string(self)
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::prefixed_api_key::{PrefixedApiKey, PrefixedApiKeyError};

    #[test]
    fn to_string_is_expected() {
        let prefix = "mycompany".to_owned();
        let short = "abcdefg".to_owned();
        let long = "bacdegadsa".to_owned();
        let expected_token = format!("{}_{}_{}", prefix, short, long);
        let pak = PrefixedApiKey::new(prefix, short, long);
        assert_eq!(pak.to_string(), expected_token)
    }

    #[test]
    fn self_from_string_works() {
        let pak_string = "mycompany_abcdefg_bacdegadsa";
        let pak_result = PrefixedApiKey::from_string(pak_string);
        assert_eq!(pak_result.is_ok(), true);
        assert_eq!(pak_result.unwrap().to_string(), pak_string);
    }

    #[test]
    fn str_into_pak() {
        let pak_string = "mycompany_abcdefg_bacdegadsa";
        let pak_result: Result<PrefixedApiKey, _> = pak_string.try_into();
        assert_eq!(pak_result.is_ok(), true);
        assert_eq!(pak_result.unwrap().to_string(), pak_string);
    }

    #[test]
    fn string_into_pak_via_as_ref() {
        let pak_string = "mycompany_abcdefg_bacdegadsa".to_owned();
        let pak_result: Result<PrefixedApiKey, _> = pak_string.as_str().try_into();
        assert_eq!(pak_result.is_ok(), true);
        assert_eq!(pak_result.unwrap().to_string(), pak_string);
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
        let mut digest = Sha256::new();
        assert_eq!(pak.long_token_hashed(&mut digest), hash);
    }

    #[test]
    fn check_debug_display_hides_secret_token() {
        let pak_string = "mycompany_CEUsS4psCmc_BddpcwWyCT3EkDjHSSTRaSK1dxtuQgbjb";

        let pak: PrefixedApiKey = pak_string.try_into().unwrap();
        let debug_string = format!("{:?}", pak);
        assert_eq!(debug_string, "PrefixedApiKey { prefix: \"mycompany\", short_token: \"CEUsS4psCmc\", long_token: \"***\" }");
    }
}
