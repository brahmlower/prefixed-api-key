# Change Log

All notable changes to this project are documented below.

The format is based on [keep a changelog](http://keepachangelog.com).


## [Unreleased]

### Added
- Added this changelog

### Changed
- Added Minimum Supported Rust Version (MSRV) to the package (1.60.0)
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
