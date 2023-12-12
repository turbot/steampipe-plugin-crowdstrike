---
title: "Steampipe Table: crowdstrike_user - Query Crowdstrike Users using SQL"
description: "Allows users to query Crowdstrike Users, specifically user details such as user ID, email, name, created and last login times, providing insights into user activities and behaviors."
---

# Table: crowdstrike_user - Query Crowdstrike Users using SQL

Crowdstrike is a cloud-native endpoint security platform that combines next-generation antivirus, endpoint detection and response (EDR), managed threat hunting, and threat intelligence. It uses artificial intelligence (AI) to analyze behavior on endpoints and networks, helping to stop breaches and mitigate threat activity. Crowdstrike Users are individual accounts within the Crowdstrike platform, each with their specific roles and permissions.

## Table Usage Guide

The `crowdstrike_user` table provides insights into user accounts within the Crowdstrike platform. As a security analyst, explore user-specific details through this table, including user ID, email, name, and activity times. Utilize it to uncover information about user behaviors, such as login patterns, and to verify user roles and permissions.

## Examples

### Basic info
Explore which users are registered in the system, gaining insights into the scope of your user base. This can be beneficial in assessing the scale of your operations and identifying potential areas for user engagement or growth.

```sql+postgres
select
  first_name,
  last_name,
  uid
from
  crowdstrike_user
```

```sql+sqlite
select
  first_name,
  last_name,
  uid
from
  crowdstrike_user
```

### List users with specific roles
Explore which users have been assigned specific roles such as 'custom_ioas_manager' or 'dashboard_admin'. This can be useful in managing user permissions and ensuring appropriate access controls are in place.

```sql+postgres
select
  first_name,
  last_name,
  uid
from
  crowdstrike_user
where
  roles ?| array['custom_ioas_manager', 'dashboard_admin']
```

```sql+sqlite
Error: SQLite does not support array operations and the '?' operator used in PostgreSQL.
```