use clap::{arg, Arg, Command};

mod command_check;
mod command_generate;
mod config;

use command_check::check;
use command_generate::generate;
use config::{load_config, Config};

fn cli(config: &mut Config) -> Command {
    // rng config
    let mut rng_arg = Arg::new("rng")
        .short('r')
        .long("rng")
        .takes_value(true)
        .help("The rng source [Options: osrng]");

    if config.rng.is_some() {
        let rng_default = config.rng.as_ref().unwrap();
        rng_arg = rng_arg.default_value(rng_default)
    }

    // digest config
    let mut digest_arg = Arg::new("digest")
        .short('d')
        .long("digest")
        .takes_value(true)
        .help("The hashing digest [Options: sha256]");

    if config.digest.is_some() {
        let digest_default = config.digest.as_ref().unwrap();
        digest_arg = digest_arg.default_value(digest_default)
    }

    // short token length config
    let mut short_length_arg = Arg::new("short-token-length")
        .short('s')
        .long("short-length")
        .takes_value(true)
        .help("Length of the short token");

    if config.short_token_length.is_some() {
        let short_length_default = config.short_token_length_str.as_ref().unwrap();
        short_length_arg = short_length_arg.default_value(short_length_default)
    }

    // short token prefix config
    let mut short_prefix_arg = Arg::new("short-token-prefix")
        .short('p')
        .long("short-prefix")
        .takes_value(true)
        .help("Prefix string for the short token");

    if config.short_token_prefix.is_some() {
        let short_prefix_default = config.short_token_prefix.as_ref().unwrap();
        short_prefix_arg = short_prefix_arg.default_value(short_prefix_default)
    }

    // long token length config
    let mut long_length_arg = Arg::new("long-token-length")
        .short('l')
        .long("long-length")
        .takes_value(true)
        .help("Length of the long token");

    if config.long_token_length.is_some() {
        let long_length_default = config.long_token_length_str.as_ref().unwrap();
        long_length_arg = long_length_arg.default_value(long_length_default)
    }

    Command::new("pakcli")
        .about("An example utility for creating/validation Prefixed API Keys")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("generate")
                .about("Generate a new key")
                .arg(arg!(<PREFIX> "The key prefix"))
                .arg_required_else_help(true)
                .arg(rng_arg)
                .arg_required_else_help(true)
                .arg(digest_arg.clone())
                .arg_required_else_help(true)
                .arg(short_length_arg)
                .arg(short_prefix_arg)
                .arg(long_length_arg),
        )
        .subcommand(
            Command::new("check")
                .about("Checks if a key is valid")
                .arg_required_else_help(true)
                .arg(arg!(<TOKEN> "The token to verify"))
                .arg_required_else_help(true)
                .arg(arg!(<HASH> "The expected hash value"))
                .arg_required_else_help(true)
                .arg(digest_arg.clone())
                .arg_required_else_help(true),
        )
}

fn main() {
    let filename = "pak_config.toml";
    let mut config = load_config(filename);
    config.short_length_as_str();
    config.long_length_as_str();

    let matches = cli(&mut config).get_matches();

    match matches.subcommand() {
        Some(("check", sub_matches)) => check(sub_matches),
        Some(("generate", sub_matches)) => generate(sub_matches),
        _ => unreachable!(),
    }
}
