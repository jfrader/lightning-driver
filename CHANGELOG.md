# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0]

### Added

- First release of the Lightning Driver backend for managing LND (gRPC and REST),
  Core Lightning (REST) and Bitcoin Core (RPC) nodes from one configuration.
- `lightning-client`: shared node and operation models, monetary types, settings
  and validation, including local BOLT11 invoice decoding.
- `api-server`: HTTP API and host enrollment/recovery commands, passkey and Nostr
  authentication, persistent sessions, node reads and policy-checked mutations
  backed by a SQLite operation journal.
- Disposable synthetic nodes for development and tests, systemd installation
  scripts and an operations runbook.

[1.0.0]: https://github.com/jfrader/lightning-driver/releases/tag/v1.0.0
