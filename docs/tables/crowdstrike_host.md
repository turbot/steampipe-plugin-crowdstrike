# Table: crowdstrike_host

Hosts are endpoints that run the Falcon sensor.

## Examples

### Basic info

```sql
select
  instance_id,
  hostname,
  last_login_timestamp
from
  crowdstrike_host
```

### List hosts which have been inactive for the last 3 months

```sql
select
  instance_id,
  hostname,
  last_login_timestamp
from
  crowdstrike_host
where
  last_login_timestamp < (current_date - interval '3months')
```
