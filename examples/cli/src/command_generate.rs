use clap::ArgMatches;
use prefixed_api_key::PrefixedApiKeyController;
use prefixed_api_key::sha2::Digest;

pub fn generate(matches: &ArgMatches) {
    let prefix = matches.get_one::<String>("PREFIX").map(String::as_str);

    // Generate configs
    let rng_name = matches.get_one::<String>("rng").map(String::as_str);
    let digest_name = matches.get_one::<String>("digest").map(String::as_str);
    let short_length = matches.get_one::<String>("short-token-length").map(|v| v.parse::<usize>().unwrap());
    let short_prefix = matches.get_one::<String>("short-token-prefix").map(String::as_str);
    let long_length = matches.get_one::<String>("long-token-length").map(|v| v.parse::<usize>().unwrap());

    let rng_source = match rng_name.unwrap() {
        "osrng" => prefixed_api_key::rand::rngs::OsRng,
        _ => panic!("unsupported rng type")
    };

    let digest = match digest_name.unwrap() {
        "sha256" => prefixed_api_key::sha2::Sha256::new(),
        _ => panic!("unsupported digest type")
    };

    let mut controller = PrefixedApiKeyController::new(
        prefix.unwrap().to_string(),
        rng_source,
        digest,
        short_prefix.map(|v| v.to_string()),
        short_length.unwrap(),
        long_length.unwrap(),
    );

    let (pak, hash) = controller.generate_key_and_hash();
    println!("PAK:\t{}\nHash:\t{}", pak.to_string(), hash);
}