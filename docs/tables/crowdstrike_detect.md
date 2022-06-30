# Table: crowdstrike_detect

Detections are events identified by Falcon sensors on the hosts in your environment.

## Examples

### Basic info

```sql
select
  detection_id,
  created_timestamp
from
  crowdstrike_detect
```

### List detections from the last 3 months

```sql
select
  detection_id,
  created_timestamp
from
  crowdstrike_detect
where
  created_timestamp > current_date - interval '3 months';
```

### Select a specific detection

```sql
select
  detection_id,
  created_timestamp
from
  crowdstrike_detect
where
  detection_id = 'ldt:6f8d8xxxx5b44xxxxxxxxxxb04e0acfa:423017xxxxxxxxxx41'
```
