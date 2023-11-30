---
title: "Steampipe Table: crowdstrike_host - Query CrowdStrike Hosts using SQL"
description: "Allows users to query CrowdStrike Hosts, specifically providing details about the host's ID, hostname, and associated metadata."
---

# Table: crowdstrike_host - Query CrowdStrike Hosts using SQL

CrowdStrike Hosts is a resource within CrowdStrike that provides a comprehensive view of the hosts within a network. It offers information about the host's ID, hostname, and other associated metadata. This information is crucial in understanding the state and security of the hosts within a network.

## Table Usage Guide

The `crowdstrike_host` table provides insights into the hosts within CrowdStrike. As a cybersecurity analyst, you can explore host-specific details through this table, including the host's ID, hostname, and associated metadata. Utilize it to uncover information about hosts, such as their state, security details, and other related information.

## Examples

### Basic info
Explore which instances have been accessed recently by analyzing the last login timestamp. This can help in identifying unusual activity or assessing the usage patterns of your system.

```sql
select
  instance_id,
  hostname,
  last_login_timestamp
from
  crowdstrike_host;
```

### List hosts which have been inactive for the last 3 months
Explore which hosts have been inactive in the past three months. This can be used to identify potential security risks or unnecessary resources that could be decommissioned to save costs.

```sql
select
  instance_id,
  hostname,
  last_login_timestamp
from
  crowdstrike_host
where
  last_login_timestamp < current_date - interval '3 months';
```

### List hosts which have at least one `prevention` policy applied
Gain insights into the systems where at least one preventative measure has been applied, which can help in understanding the security measures taken and identifying areas that may need additional protection.

```sql
select
  hostname,
  policies
from
  crowdstrike_host,
  jsonb_array_elements(policies) as t
where
  t ->> 'policy_type' = 'prevention';
```

### List hosts which do not have `firewall` applied
Explore which hosts lack a firewall application, enabling you to identify potential vulnerabilities and enhance your system's security measures.

```sql
select
  hostname,
  device_policies
from
  crowdstrike_host
where
  (device_policies -> 'firewall' -> 'applied')::bool = false;
```

### List hosts which are operating in reduced functionality mode
Discover the segments that are operating in a reduced functionality mode. This is useful to identify areas where performance may be impacted and to plan for necessary upgrades or troubleshooting.

```sql
select
  hostname,
  device_policies
from
  crowdstrike_host
where
  reduced_functionality_mode = 'yes';
```

### List hosts which are known to have critical open vulnerabilities
This query helps to identify the hosts that are exposed to open critical vulnerabilities. In a practical scenario, this can be used to prioritize security measures and direct resources to protect the most vulnerable parts of your network.

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