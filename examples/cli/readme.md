
# pakcli

This is an example cli that shows usage of the prefixed-api-key library. It can generate a new key, and check and existing key.

## Configuration

Configurations for token length, prefix, digest and rng source can all be provided via cli options, but they can also be set within a `pak_config.toml` file for convenience. An example toml file is provided in this repo, and can be used by running:

```shell
cp pak_config.toml.example pak_config.toml
```

## Generating a new key

A new token can be generated using the `cargo run -- generate` command. It will provide the new api key and the hash of the long token in the output:

```shell
$ cargo run -- generate foobarinc
PAK:	foobarinc_N5vKc5FMofm_qtgdkcSBwnBC1uMY4TCT37zLuSsp17qyUbU29vHZJ4pNB29qFFY5uCcAqJdVzGLmR
Hash:	c239c03136ffdd9988c48ac97c00f3e546293b5737822c5de64334abe3235675
```

## Checking an api key

The cli doesn't implement any storage mechanism for keys it generates since this is just a demo, but you can check an api token by providing the untrusted token and the hash you expect it to match. The output will simply say if it matches or not.

```shell
$ cargo run -- check foobarinc_N5vKc5FMofm_qtgdkcSBwnBC1uMY4TCT37zLuSsp17qyUbU29vHZJ4pNB29qFFY5uCcAqJdVzGLmR aae8a24df9cbe15efd2d52a3d8d594210259ec19b2c2709a8a9a03b25de
Match:	false

% cargo run -- check foobarinc_N5vKc5FMofm_qtgdkcSBwnBC1uMY4TCT37zLuSsp17qyUbU29vHZJ4pNB29qFFY5uCcAqJdVzGLmR foobarbaz
Match:	false
```
