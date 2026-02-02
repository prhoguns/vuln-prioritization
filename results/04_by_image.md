# P4. Per image: total, critical/high, KEV hits, EOL status, and how much a patch (moving to a fixed version) would remove.

```sql
-- P4. Per image: total, critical/high, KEV hits, EOL status, and how much a patch (moving to a fixed version) would remove.
-- The old/new pairs (nginx 1.18 vs 1.27, node 14 vs 22, postgres 11 vs 16) show what "just update the base image" is worth.
select
    f.image,
    any_value(f.os_family || ' ' || f.os_version) as os,
    bool_or(f.os_eol)                             as os_end_of_life,
    count(*)                                      as findings,
    count(*) filter (where f.severity in ('CRITICAL', 'HIGH')) as crit_high,
    count(*) filter (where k.cve is not null)     as kev,
    count(*) filter (where e.epss >= 0.10)        as epss_over_10pct,
    round(100.0 * count(*) filter (where f.fixed is not null) / count(*), 1) as pct_fixable,
    round(max(e.epss), 3)                         as max_epss
from findings f
left join kev k using (cve)
left join epss e using (cve)
group by 1
order by kev desc, epss_over_10pct desc, crit_high desc;
```

| image | os | os_end_of_life | findings | crit_high | kev | epss_over_10pct | pct_fixable | max_epss |
|:---|:---|---:|---:|---:|---:|---:|---:|---:|
| node:14 | debian 10.13 | 1 | 1,452 | 592 | 9 | 68 | 77.5 | 1 |
| nginx:1.18 | debian 10.9 | 1 | 424 | 189 | 2 | 48 | 79.5 | 1 |
| nginx:1.27 | debian 12.11 | 0 | 637 | 163 | 1 | 5 | 35 | 1 |
| python:3.8-slim | debian 12.7 | 0 | 468 | 115 | 0 | 4 | 40.8 | 0.733 |
| postgres:11 | debian 9.13 | 1 | 231 | 108 | 0 | 4 | 58.9 | 0.92 |
| postgres:16 | debian 13.7 | 0 | 322 | 84 | 0 | 1 | 14.3 | 0.733 |
| node:22-slim | debian 12.15 | 0 | 240 | 67 | 0 | 1 | 7.9 | 0.733 |
| python:3.12-slim | debian 13.7 | 0 | 158 | 44 | 0 | 0 | 3.8 | 0.052 |
| ubuntu:20.04 | ubuntu 20.04 | 1 | 2 | 0 | 0 | 0 | 100 | 0.006 |
