![image](https://hub.steampipe.io/images/plugins/turbot/crowdstrike-social-graphic.png)

# CrowdStrike Plugin for Steampipe

Use SQL to query resources from [CrowdStrike](https://crowdstrike.com/).

- **[Get started →](https://hub.steampipe.io/plugins/turbot/crowdstrike)**
- Documentation: [Table definitions & examples](https://hub.steampipe.io/plugins/turbot/crowdstrike/tables)
- Community: [Join #steampipe on Slack →](https://turbot.com/community/join)
- Get involved: [Issues](https://github.com/turbot/steampipe-plugin-crowdstrike/issues)

## Quick start

Install the plugin with [Steampipe](https://steampipe.io):

```shell
steampipe plugin install crowdstrike
```

Run a query:

```sql
select
  created_timestamp,
  host_info -> 'hostname' AS hostname,
  status
from
  crowdstrike_spotlight_vulnerability
where
  created_timestamp > now() - interval '15 days';
```

## Developing

Prerequisites:

- [Steampipe](https://steampipe.io/downloads)
- [Golang](https://golang.org/doc/install)

Clone:

```sh
git clone https://github.com/turbot/steampipe-plugin-crowdstrike.git
cd steampipe-plugin-crowdstrike
```

Build, which automatically installs the new version to your `~/.steampipe/plugins` directory:

```
make
```

Configure the plugin:

```
cp config/* ~/.steampipe/config
vi ~/.steampipe/config/crowdstrike.spc
```

Try it!

```
steampipe query
> .inspect crowdstrike
```

Further reading:

- [Writing plugins](https://steampipe.io/docs/develop/writing-plugins)
- [Writing your first table](https://steampipe.io/docs/develop/writing-your-first-table)

## Contributing

Please see the [contribution guidelines](https://github.com/turbot/steampipe/blob/main/CONTRIBUTING.md) and our [code of conduct](https://github.com/turbot/steampipe/blob/main/CODE_OF_CONDUCT.md). All contributions are subject to the [Apache 2.0 open source license](https://github.com/turbot/steampipe-plugin-crowdstrike/blob/main/LICENSE).

`help wanted` issues:

- [Steampipe](https://github.com/turbot/steampipe/labels/help%20wanted)
- [CrowdStrike Plugin](https://github.com/turbot/steampipe-plugin-crowdstrike/labels/help%20wanted)
