---
title: "Steampipe Table: crowdstrike_user - Query CrowdStrike Users using SQL"
description: "Allows users to query CrowdStrike Users, providing insights into user profiles and their associated details within the CrowdStrike environment."
---

# Table: crowdstrike_user - Query CrowdStrike Users using SQL

CrowdStrike is a cybersecurity technology firm that offers endpoint security, threat intelligence, and cyberattack response services. It provides a cloud-native endpoint security platform which combines antivirus, threat intelligence, and cyberattack response functionalities. Users in CrowdStrike represent individuals who have access to the CrowdStrike Falcon platform and their profiles contain details such as email, first and last names, and roles.

## Table Usage Guide

The `crowdstrike_user` table provides insights into user profiles within CrowdStrike's endpoint security platform. As a security analyst, you can explore user-specific details through this table, including email addresses, names, and roles. Utilize it to uncover information about users, such as their access level, role assignment, and other associated details to improve your organization's security posture.

## Examples

### Basic info
Explore which users are registered in the system by identifying each one through their unique identifiers. This can be beneficial for managing user accounts and ensuring system security.

```sql
select
  first_name,
  last_name,
  uid
from
  crowdstrike_user
```

### List users with specific roles
Discover the segments of users who have been assigned specific roles such as 'custom_ioas_manager' or 'dashboard_admin'. This is particularly useful for managing user permissions and ensuring the right individuals have access to the correct roles.

```sql
select
  first_name,
  last_name,
  uid
from
  crowdstrike_user
where
  roles ?| array['custom_ioas_manager', 'dashboard_admin']
```