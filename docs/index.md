---
organization: turbot
category: ["security"]
icon_url: "/images/plugins/turbot/crowdstrike.svg"
brand_color: "#FC0000"
display_name: CrowdStrike
name: crowdstrike
description: Steampipe plugin to query resources from CrowdStrike.
og_description: Query CrowdStrike data with SQL! Open source CLI. No DB required.
og_image: "/images/plugins/turbot/crowdstrike-social-graphic.png"
---

# CrowdStrike + Steampipe

[Steampipe](https://steampipe.io) is an open source CLI to instantly query cloud APIs using SQL.

[CrowdStrike](https://crowdstrike.com) provides cloud workload and endpoint security, threat intelligence, and cyberattack response services.

For example:

```sql
select
  created_timestamp,
  host_info -> 'hostname' AS hostname,
  status
from
  crowdstrike_spotlight_vulnerability
where
  created_timestamp > (now() - interval '15 days');
```

## Documentation

- **[Table definitions & examples →](/plugins/turbot/crowdstrike/tables)**

## Get started

### Install

Download and install the latest CrowdStrike plugin:

```shell
steampipe plugin install crowdstrike
```

### Configuration

Installing the latest crowdstrike plugin will create a config file (`~/.steampipe/config/crowdstrike.spc`) with a single connection named `crowdstrike`:

```hcl
connection "crowdstrike" {
  plugin  = "crowdstrike"

  # CrowdStrike client ID
  # client_id = "4fe29d3fakeclientid"

  # CrowdStrike client secret
  # client_secret = "Z0F3MTfakesecret"

  # Falcon cloud (us-1, us-2, eu-1, us-gov-1)
  # client_cloud = "us-2"
}
```

- `client_cloud` - (required) The Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1).
- `client_id` - (required) The client ID.
- `client_secret` - (required) The client secret.

## Get involved

- Open source: https://github.com/turbot/steampipe-plugin-crowdstrike
- Community: [Slack Channel](https://steampipe.io/community/join)
