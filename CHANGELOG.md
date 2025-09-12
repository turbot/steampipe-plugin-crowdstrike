## v1.2.0 [2025-09-12]

_Deprecations_

- [crowdstrike_detection](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_detection) table has been deprecated due to missing API support. It will be removed in a future major release. Please use [crowdstrike_alert](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_alert) table instead. ([#57](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/57))

_What's new?_

- New tables added
  - [crowdstrike_alert](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_alert) ([#57](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/57))

_Dependencies_

- Recompiled plugin with `github.com/crowdstrike/gofalcon` with [v0.16.0](https://github.com/CrowdStrike/gofalcon/releases/tag/v0.16.0). ([#57](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/57))
- Recompiled plugin with Go version `1.24`. ([#55](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/55))
- Recompiled plugin with [steampipe-plugin-sdk v5.13.0](https://github.com/turbot/steampipe-plugin-sdk/blob/develop/CHANGELOG.md#v5130-2025-07-21) that addresses critical and high vulnerabilities in dependent packages. ([#55](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/55))

## v1.1.1 [2025-04-18]

_Bug fixes_

- Fixed Linux AMD64 plugin build failures for `Postgres 14 FDW`, `Postgres 15 FDW`, and `SQLite Extension` by upgrading GitHub Actions runners from `ubuntu-20.04` to `ubuntu-22.04`.

## v1.1.0 [2025-04-17]

_Dependencies_

- Recompiled plugin with Go version `1.23.1`. ([#50](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/50))
- Recompiled plugin with [steampipe-plugin-sdk v5.11.5](https://github.com/turbot/steampipe-plugin-sdk/blob/v5.11.5/CHANGELOG.md#v5115-2025-03-31) that addresses critical and high vulnerabilities in dependent packages. ([#50](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/50))

## v1.0.0 [2024-10-22]

There are no significant changes in this plugin version; it has been released to align with [Steampipe's v1.0.0](https://steampipe.io/changelog/steampipe-cli-v1-0-0) release. This plugin adheres to [semantic versioning](https://semver.org/#semantic-versioning-specification-semver), ensuring backward compatibility within each major version.

_Dependencies_

- Recompiled plugin with Go version `1.22`. ([#47](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/47))
- Recompiled plugin with [steampipe-plugin-sdk v5.10.4](https://github.com/turbot/steampipe-plugin-sdk/blob/develop/CHANGELOG.md#v5104-2024-08-29) that fixes logging in the plugin export tool. ([#47](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/47))

## v0.4.0 [2023-12-12]

_What's new?_

- The plugin can now be downloaded and used with the [Steampipe CLI](https://steampipe.io/docs), as a [Postgres FDW](https://steampipe.io/docs/steampipe_postgres/overview), as a [SQLite extension](https://steampipe.io/docs//steampipe_sqlite/overview) and as a standalone [exporter](https://steampipe.io/docs/steampipe_export/overview). ([#32](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/32))
- The table docs have been updated to provide corresponding example queries for Postgres FDW and SQLite extension. ([#32](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/32))
- Docs license updated to match Steampipe [CC BY-NC-ND license](https://github.com/turbot/steampipe-plugin-crowdstrike/blob/main/docs/LICENSE). ([#32](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/32))

_Dependencies_

- Recompiled plugin with [steampipe-plugin-sdk v5.8.0](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v580-2023-12-11) that includes plugin server encapsulation for in-process and GRPC usage, adding Steampipe Plugin SDK version to  column `_ctx`, and fixing connection and potential divide-by-zero bugs. ([#31](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/31))

## v0.3.2 [2023-12-06]

_Bug fixes_

- Fixed the invalid Go module path of the plugin. ([#27](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/27))

## v0.3.1 [2023-10-05]

_Dependencies_

- Recompiled plugin with [steampipe-plugin-sdk v5.6.2](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v562-2023-10-03) which prevents nil pointer reference errors for implicit hydrate configs. ([#16](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/16))

## v0.3.0 [2023-10-02]

_Dependencies_

- Upgraded to [steampipe-plugin-sdk v5.6.1](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v561-2023-09-29) with support for rate limiters. ([#13](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/13))
- Recompiled plugin with Go version `1.21`. ([#13](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/13))

## v0.2.0 [2023-03-23]

_Dependencies_

- Recompiled plugin with [steampipe-plugin-sdk v5.3.0](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v530-2023-03-16) which includes fixes for query cache pending item mechanism and aggregator connections not working for dynamic tables. ([#5](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/5))

## v0.1.0 [2022-09-27]

_Dependencies_

- Recompiled plugin with [steampipe-plugin-sdk v4.1.7](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v417-2022-09-08) which includes several caching and memory management improvements. ([#2](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/2))
- Recompiled plugin with Go version `1.19`. ([#2](https://github.com/turbot/steampipe-plugin-crowdstrike/pull/2))

 ## v0.0.1 [2022-07-07]

Thanks to [@slartibastfast](https://github.com/slartibastfast) for all of his help making this plugin possible!

_What's new?_

- New tables added
  - [crowdstrike_detection](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_detection)
  - [crowdstrike_host](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_host)
  - [crowdstrike_intel_actor](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_intel_actor)
  - [crowdstrike_spotlight_vulnerability](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_spotlight_vulnerability)
  - [crowdstrike_user](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_user)
  - [crowdstrike_zta_assessment](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_zta_assessment)
  - [crowdstrike_zta_compliance](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables/crowdstrike_zta_compliance)
