-- P1. The headline: how many findings there are by CVSS severity, versus how many are actually likely to be exploited.
-- Counting CRITICAL/HIGH is what most vulnerability reports do. Joining KEV and EPSS is what changes the answer.
select
    severity,
    count(*)                                              as findings,
    count(distinct cve)                                   as distinct_cves,
    count(*) filter (where k.cve is not null)             as in_cisa_kev,
    count(*) filter (where e.epss >= 0.10)                as epss_over_10pct,
    count(*) filter (where f.fixed is not null)           as fix_available,
    round(100.0 * count(*) filter (where f.fixed is not null) / count(*), 1) as pct_fixable
from findings f
left join kev k using (cve)
left join epss e using (cve)
group by 1
order by case severity when 'CRITICAL' then 1 when 'HIGH' then 2 when 'MEDIUM' then 3 when 'LOW' then 4 else 5 end;
