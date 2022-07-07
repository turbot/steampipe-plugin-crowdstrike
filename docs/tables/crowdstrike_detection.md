# Table: crowdstrike_detection

Detections are events identified by Falcon sensors on the hosts in your environment.

## Examples

### Basic info

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection;
```

### List detections from the last 3 months

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  created_timestamp > current_date - interval '3 months';
```

### List detections with a `severity` over a threshold

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  max_severity > 50;
```

### List detections in devices which belong to a network

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  device ->> 'external_ip' as external_ip,
  network((device ->> 'external_ip')::INET) as network
from
  crowdstrike_detection
where
  network((device ->> 'external_ip')::INET) = '119.18.0.0/28';
```

### List open detections

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  status = 'open';
```

### List open detections from the last 4 days

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  status = 'open'
  and now() - created_timestamp > interval '4 days';
```

### Get a specific detection

```sql
select
  detection_id,
  created_timestamp,
  device ->> 'device_id' as device_id,
  device ->> 'hostname' as hostname,
  device ->> 'platform_name' as platform_name,
  device ->> 'os_version' as os_version,
  status
from
  crowdstrike_detection
where
  detection_id = 'ldt:6f8d8xxxx5b44xxxxxxxxxxb04e0acfa:423017xxxxxxxxxx41';
```
