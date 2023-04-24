use clap::ArgMatches;
use prefixed_api_key::PrefixedApiKey;
use prefixed_api_key::PrefixedApiKeyController;

pub fn check(matches: &ArgMatches) {
    let token = matches
        .get_one::<String>("TOKEN")
        .map(String::as_str)
        .expect("Token is required");
    let hash = matches
        .get_one::<String>("HASH")
        .map(String::as_str)
        .expect("Hash is required");

    // Generate configs
    let digest_name = matches.get_one::<String>("digest").map(String::as_str);

    // Can't create a controller without an rng source, even though we won't be using it here
    // so we're just going to use the OsRng source 🤷‍♂️
    // TODO: Provide a way to hash/check tokens without requiring an RNG
    let mut builder = PrefixedApiKeyController::configure()
        .prefix("".to_owned())
        .rng_osrng()
        .default_lengths();

    builder = match digest_name.unwrap() {
        "sha256" => builder.digest_sha256(),
        _ => panic!("unsupported digest type"),
    };

    let controller = builder.finalize().expect("failed to create pak controller");

    let pak: PrefixedApiKey = token.try_into().expect("token was incorrectly formatted");
    let result = controller.check_hash(&pak, hash);
    println!("Match:\t{}", result);
}
