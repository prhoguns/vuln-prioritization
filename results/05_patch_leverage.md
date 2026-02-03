# P5. Which single package upgrades close the most findings? Patch the package, not the CVE.

```sql
-- P5. Which single package upgrades close the most findings? Patch the package, not the CVE.
select
    image, package, installed,
    max(fixed)                                        as upgrade_to,
    count(*)                                          as findings_closed,
    count(*) filter (where severity in ('CRITICAL', 'HIGH')) as crit_high_closed,
    count(*) filter (where k.cve is not null)         as kev_closed,
    round(max(e.epss), 3)                             as max_epss_closed
from findings f
left join kev k using (cve)
left join epss e using (cve)
where fixed is not null
group by 1, 2, 3
order by kev_closed desc, crit_high_closed desc, findings_closed desc
limit 15;
```

| image | package | installed | upgrade_to | findings_closed | crit_high_closed | kev_closed | max_epss_closed |
|:---|:---|:---|:---|---:|---:|---:|---:|
| node:14 | linux-libc-dev | 4.19.269-1 | 4.19.316-1 | 432 | 144 | 4 | 0.281 |
| nginx:1.18 | libwebp6 | 0.6.1-2 | 0.6.1-2+deb10u3 | 13 | 13 | 1 | 1 |
| nginx:1.18 | libnghttp2-14 | 1.36.0-2+deb10u1 | 1.36.0-2+deb10u3 | 3 | 2 | 1 | 1 |
| node:14 | libnghttp2-14 | 1.36.0-2+deb10u1 | 1.36.0-2+deb10u3 | 3 | 2 | 1 | 1 |
| node:14 | libwebpdemux2 | 0.6.1-2+deb10u1 | 0.6.1-2+deb10u3 | 2 | 2 | 1 | 1 |
| node:14 | libwebp-dev | 0.6.1-2+deb10u1 | 0.6.1-2+deb10u3 | 2 | 2 | 1 | 1 |
| node:14 | libwebp6 | 0.6.1-2+deb10u1 | 0.6.1-2+deb10u3 | 2 | 2 | 1 | 1 |
| node:14 | libwebpmux3 | 0.6.1-2+deb10u1 | 0.6.1-2+deb10u3 | 2 | 2 | 1 | 1 |
| postgres:11 | stdlib | v1.16.7 | 1.25.9, 1.26.2 | 121 | 65 | 0 | 0.92 |
| postgres:16 | stdlib | v1.24.6 | 1.25.9, 1.26.2 | 45 | 22 | 0 | 0.022 |
| nginx:1.18 | libexpat1 | 2.2.6-2+deb10u1 | 2.2.6-2+deb10u7 | 19 | 17 | 0 | 0.359 |
| nginx:1.18 | libc-bin | 2.28-10 | 2.28-10+deb10u4 | 19 | 10 | 0 | 0.883 |
| nginx:1.18 | libc6 | 2.28-10 | 2.28-10+deb10u4 | 19 | 10 | 0 | 0.883 |
| node:14 | python2.7-minimal | 2.7.16-2+deb10u1 | 2.7.16-2+deb10u4 | 17 | 10 | 0 | 0.36 |
| node:14 | python2.7 | 2.7.16-2+deb10u1 | 2.7.16-2+deb10u4 | 17 | 10 | 0 | 0.36 |
