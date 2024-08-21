# Change Log

All notable changes to this project are documented below.

The format is based on [keep a changelog](http://keepachangelog.com), but includes an added
"Housekeeping" change type for denoting project changes that don't impact direct usage of
the library.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the
addition of pre-1.0.0 version compatibility behavior described by [the rust docs here](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-cratesio).



## [Unreleased]

## [0.3.0] - 2024-08-20

### Added
- Added type aliases for the PrefixedApiKeyController with various generics
  - This is a huge quality of life improvement for working with the controller:
    ```rust
    let controller_result: Result<PakControllerOsSha256, BuilderError> =
        ControllerBuilder::new()
            .prefix("mycompany".to_owned())
            .seam_defaults()
            .finalize();
    ```
- Added `try_generate_key` and `try_generate_key_and_hash` methods for safely generating new PAKs.

### Changed
- 🚨 Bumped MSRV to 1.61.0

### Housekeeping
- Small documentation & test fixes

## [0.2.0] - 2024-04-06

### Added
- Added this changelog
- Added Minimum Supported Rust Version (MSRV) to the package (1.60.0)

### Changed
- 🚨 BREAKING: Removed `mut` requirement on `PrefixedApiKeyController` (https://github.com/brahmlower/prefixed-api-key/pull/15)
  - rng source must now implement `Clone`

### Housekeeping
- CI now verifies MSRV
- CI now runs weekly (to ensure continued compatibility with nightly/beta)
- Docs cleanup on example/cli readme

## [0.1.0] - 2023-04-24

### Changed
- Improved error type for ControllerBuilder finalize failures
- `PrefixedApiKeyController.check_hash` no longer needs &mut self
- `PrefixedApiKeyController` no longer holds digest instance
- very slight docs improvements (lots more improvements needed in future releases)

### Fixed
- Fixed issue with builds on m1/m2 macs
