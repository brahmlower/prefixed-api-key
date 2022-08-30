use clap::ArgMatches;
use prefixed_api_key::PrefixedApiKey;
use prefixed_api_key::sha2::Digest;
use prefixed_api_key::PrefixedApiKeyController;

pub fn check(matches: &ArgMatches) {
    let token = matches.get_one::<String>("TOKEN").map(String::as_str);
    let hash = matches.get_one::<String>("HASH").map(String::as_str);

    // Generate configs
    let digest_name = matches.get_one::<String>("digest").map(String::as_str);

    // Can't create a controller without an rng source, even though we won't be using it here
    // so we're just going to use the OsRng source :shrug:
    // TODO: Provide a way to hash/check tokens without requiring an RNG
    let rng_source = prefixed_api_key::rand::rngs::OsRng;

    let digest = match digest_name.unwrap() {
        "sha256" => prefixed_api_key::sha2::Sha256::new(),
        _ => panic!("unsupported digest type")
    };

    let mut controller = PrefixedApiKeyController::new(
        "".to_owned(),
        rng_source,
        digest,
        None,
        0, // short token length not required for checking tokens
        0, // long token length not required for checking tokens
    );

    let pak: PrefixedApiKey = token.unwrap().try_into().expect("token was incorrectly formatted");
    let result = controller.check_hash(&pak, hash.unwrap().to_string());
    println!("Match:\t{}", result);
}