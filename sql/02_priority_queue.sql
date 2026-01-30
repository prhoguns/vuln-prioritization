-- P2. The prioritised work queue. Tier logic, in order:
--   P0  in CISA KEV (exploited in the wild) and a fix exists            -> patch this week, no discussion
--   P1  EPSS >= 0.10 (top ~5% most likely to be exploited) and fixable   -> this sprint
--   P2  CRITICAL/HIGH with EPSS >= 0.01 and fixable                       -> next sprint
--   P3  everything else fixable                                           -> routine patch cadence
--   P4  no fix available                                                  -> track, mitigate, or accept
select
    case
        when k.cve is not null and f.fixed is not null then 'P0'
        when e.epss >= 0.10 and f.fixed is not null then 'P1'
        when f.severity in ('CRITICAL', 'HIGH') and e.epss >= 0.01 and f.fixed is not null then 'P2'
        when f.fixed is not null then 'P3'
        else 'P4'
    end                                   as tier,
    f.image, f.package, f.cve, f.severity, f.cvss_v3,
    round(e.epss, 4)                      as epss,
    k.date_added                          as kev_added,
    k.ransomware                          as kev_ransomware,
    f.installed, f.fixed
from findings f
left join kev k using (cve)
left join epss e using (cve)
order by tier, e.epss desc nulls last, f.cvss_v3 desc nulls last
limit 40;
