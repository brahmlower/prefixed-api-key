use std::fs;
use serde_derive::Deserialize;
use toml;

#[derive(Deserialize)]
pub struct Config {
    pub digest: Option<String>,
    pub rng: Option<String>,
    pub prefix: Option<String>,
    pub short_token_length: Option<usize>,
    pub short_token_length_str: Option<String>,
    pub short_token_prefix: Option<String>,
    pub long_token_length: Option<usize>,
    pub long_token_length_str: Option<String>
}

impl Config {
    pub fn short_length_as_str(&mut self) {
        self.short_token_length_str = self.short_token_length.map(|v| format!("{}", v));
    }

    pub fn long_length_as_str(&mut self) {
        self.long_token_length_str = self.long_token_length.map(|v| format!("{}", v));
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            digest: None,
            rng: None,
            prefix: None,
            short_token_length: None,
            short_token_length_str: None,
            short_token_prefix: None,
            long_token_length: None,
            long_token_length_str: None,
        }
    }
}

pub fn load_config(filename: &str) -> Config {
    fs::read_to_string(filename)
        .ok()
        .and_then(|c| toml::from_str(&c).ok())
        .or_else(|| Some(Config::default()))
        .unwrap()
}
