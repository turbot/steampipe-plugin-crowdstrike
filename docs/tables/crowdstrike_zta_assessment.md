# Table: crowdstrike_zta_assessment

Zero Trust Assessment is a Falcon Insight feature that monitors the native OS security settings and applied sensor policies of Windows 10 and macOS endpoints to gauge the device security posture of managed assets within an organization. The metrics derived from these assessments can be used by IdP, NAC, and other solutions to provide additional data points around device health and security posture as part of their respective conditional access capabilities.

## Examples

### Basic info

```sql
select
  device_id,
  aid,
  assessment,
  event_platform
from
  crowdstrike_zta_assessment
```

### List ZeroTrust assessments with assessment score over a threshold

```sql
select
  device_id,
  aid,
  assessment,
  event_platform,
  assessment ->> 'overall' as overall
from
  crowdstrike_zta_assessment
where
  (assessment ->> 'overall')::int > 92
```

### List device IDs with firewalls disabled

```sql
select
  device_id,
  event_platform
from
  crowdstrike_zta_assessment,
  jsonb_array_elements(assessment_items -> 'os_signals') as t
where
  t ->> 'signal_id' like 'application_firewall_%'
  and t ->> 'meets_criteria' = 'no'
```
