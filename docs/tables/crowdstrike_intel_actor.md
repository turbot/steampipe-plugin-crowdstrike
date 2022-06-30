# Table: crowdstrike_intel_actor

With the Actors API, Falcon Intel subscribers can search for data about actors that CrowdStrike is tracking.

## Examples

### Basic info

```sql
select
  name,
  slug,
  description,
  actor_type
from
  crowdstrike_intel_actor
```

### List hosts which have been active in the last 3 months

```sql
select
  name,
  slug,
  description,
  actor_type
from
  crowdstrike_intel_actor
where
  last_activity_date > (current_date - (interval '3months'))
```
