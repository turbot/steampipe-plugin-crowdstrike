# Table: crowdstrike_zta_compliance

Summarizes Zero Trust Assessment data.

## Examples

### Basic info

```sql
select
  average_overall_score,
  num_aids,
  platforms
from
  crowdstrike_zta_compliance
```

### List compliance information per platform

```sql
select
  p ->> 'name' as os_platform,
  p ->> 'average_overall_score' as overall_zta_score,
  p ->> 'num_aids' as no_of_assessments
from
  crowdstrike_zta_compliance,
  jsonb_array_elements(platforms) as p
```
