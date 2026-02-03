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
