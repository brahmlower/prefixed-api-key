use clap::ArgMatches;
use prefixed_api_key::PrefixedApiKeyController;

pub fn generate(matches: &ArgMatches) {
    let prefix = matches.get_one::<String>("PREFIX").map(String::as_str);

    // Generate configs
    let rng_name = matches
        .get_one::<String>("rng")
        .map(String::as_str)
        .expect("RNG name is required");
    let digest_name = matches
        .get_one::<String>("digest")
        .map(String::as_str)
        .expect("Digest name is required");
    let short_length = matches
        .get_one::<String>("short-token-length")
        .map(|v| v.parse::<usize>().expect("invalid usize value"))
        .expect("Short token length is required");
    let short_prefix = matches
        .get_one::<String>("short-token-prefix")
        .map(String::as_str);
    let long_length = matches
        .get_one::<String>("long-token-length")
        .map(|v| v.parse::<usize>().expect("invalid usize value"))
        .expect("Long token length is required");

    let mut builder = PrefixedApiKeyController::configure()
        .prefix(prefix.unwrap().to_string())
        .rng_osrng()
        .short_token_length(short_length)
        .short_token_prefix(short_prefix.map(|v| v.to_owned()))
        .long_token_length(long_length);

    builder = match rng_name {
        "osrng" => builder.rng_osrng(),
        _ => panic!("unsupported rng type"),
    };

    builder = match digest_name {
        "sha256" => builder.digest_sha256(),
        _ => panic!("unsupported digest type"),
    };

    let mut controller = builder.finalize().expect("failed to create pak controller");

    let (pak, hash) = controller.generate_key_and_hash();
    println!("PAK:\t{}\nHash:\t{}", pak.to_string(), hash);
}
