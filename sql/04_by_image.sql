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
