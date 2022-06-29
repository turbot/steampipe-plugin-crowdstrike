# Table: crowdstrike_detect

Hosts are endpoints that run the Falcon sensor.

## Examples

### List detections from the last 3 months

```sql
select
  instance_id,
  hostname,
  last_login_timestamp
from
  crowdstrike_host
```

### List hosts which have not been logged in to in the last 3 months

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
