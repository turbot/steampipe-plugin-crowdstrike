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

### List hosts which are known to have critical `open` vulnerabilities

```sql
select
  vuln.host_info ->> 'hostname' as hostname,
  vuln.cve,
  vuln.status as vuln_status,
  hosts.email,
  hosts.status as host_status
from
  crowdstrike_host hosts
  left join
    crowdstrike_spotlight_vulnerability as vuln
    on hosts.hostname = vuln.host_info ->> 'hostname'
where
  vuln.cve ->> 'exprt_rating' = 'CRITICAL'
  and vuln.status = 'open';
```
