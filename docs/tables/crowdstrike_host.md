---
title: "Steampipe Table: crowdstrike_host - Query CrowdStrike Hosts using SQL"
description: "Allows users to query CrowdStrike Hosts, specifically the host details, providing insights into host security posture and potential vulnerabilities."
---

# Table: crowdstrike_host - Query CrowdStrike Hosts using SQL

CrowdStrike is a cybersecurity technology company that offers endpoint protection, threat intelligence, and cyberattack response services. It provides a cloud-native endpoint security platform combines Next-Gen Av, EDR, and managed hunting services into a single solution. With CrowdStrike, organizations can prevent cyberattacks, detect malicious activities, respond to security incidents, and forecast future threats.

## Table Usage Guide

The `crowdstrike_host` table offers insights into the hosts within CrowdStrike's cybersecurity technology. As a cybersecurity analyst, you can delve into host-specific details through this table, including the host's ID, hostname, and status. This table can be utilized to uncover crucial information about hosts, such as their current security posture, potential vulnerabilities, and the overall threat landscape.

## Examples

### Basic info
Explore which instances have recently been accessed by reviewing the last login timestamp. This can be useful for monitoring activity and identifying potential unauthorized access.

```sql+postgres
select
  instance_id,
  hostname,
  last_login_timestamp
from
  crowdstrike_host;
```

```sql+sqlite
select
  instance_id,
  hostname,
  last_login_timestamp
from
  crowdstrike_host;
```

### List hosts which have been inactive for the last 3 months
Uncover the details of hosts that have not been active in the past three months. This is useful for identifying potential security risks or for optimizing resource allocation.

```sql+postgres
select
  instance_id,
  hostname,
  last_login_timestamp
from
  crowdstrike_host
where
  last_login_timestamp < current_date - interval '3 months';
```

```sql+sqlite
select
  instance_id,
  hostname,
  last_login_timestamp
from
  crowdstrike_host
where
  last_login_timestamp < date('now','-3 months');
```

### List hosts which have at least one `prevention` policy applied
Explore which hosts have at least one prevention policy applied to them. This is useful for identifying areas where proactive measures are being taken to prevent potential security threats.

```sql+postgres
select
  hostname,
  policies
from
  crowdstrike_host,
  jsonb_array_elements(policies) as t
where
  t ->> 'policy_type' = 'prevention';
```

```sql+sqlite
select
  hostname,
  policies
from
  crowdstrike_host,
  json_each(policies) as t
where
  json_extract(t.value, '$.policy_type') = 'prevention';
```

### List hosts which do not have `firewall` applied
Uncover the details of hosts that lack a firewall application, allowing for enhanced security management and potential risk mitigation.

```sql+postgres
select
  hostname,
  device_policies
from
  crowdstrike_host
where
  (device_policies -> 'firewall' -> 'applied')::bool = false;
```

```sql+sqlite
select
  hostname,
  device_policies
from
  crowdstrike_host
where
  json_extract(json_extract(device_policies, '$.firewall'), '$.applied') = 'false';
```

### List hosts which are operating in reduced functionality mode
Identify instances where certain hosts are operating in a reduced functionality mode. This can be useful in assessing the overall performance and efficiency of your network.

```sql+postgres
select
  hostname,
  device_policies
from
  crowdstrike_host
where
  reduced_functionality_mode = 'yes';
```

```sql+sqlite
select
  hostname,
  device_policies
from
  crowdstrike_host
where
  reduced_functionality_mode = 'yes';
```

### List hosts which are known to have critical open vulnerabilities
Discover the segments that have known critical vulnerabilities to better manage and mitigate potential security risks. This query is useful in identifying and prioritizing the hosts that require immediate attention, thereby enhancing your system's overall security posture.

```sql+postgres
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

```sql+sqlite
select
  json_extract(vuln.host_info, '$.hostname') as hostname,
  vuln.cve,
  vuln.status as vuln_status,
  hosts.email,
  hosts.status as host_status
from
  crowdstrike_host hosts
  left join
    crowdstrike_spotlight_vulnerability as vuln
    on hosts.hostname = json_extract(vuln.host_info, '$.hostname')
where
  json_extract(vuln.cve, '$.exprt_rating') = 'CRITICAL'
  and vuln.status = 'open';
```