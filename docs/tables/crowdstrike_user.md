# Table: crowdstrike_user

Users in the Falcon system.

## Examples

### Basic info

```sql
select
  first_name,
  last_name,
  uid
from
  crowdstrike_user
```

### List users with specific roles

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
