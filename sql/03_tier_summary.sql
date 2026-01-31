-- P3. How much work is in each tier, and how it splits by image. This is the slide for the manager.
with tiered as (
    select f.image, f.cve, f.severity, f.fixed,
        case
            when k.cve is not null and f.fixed is not null then 'P0 KEV, fixable'
            when e.epss >= 0.10 and f.fixed is not null then 'P1 EPSS>=10%, fixable'
            when f.severity in ('CRITICAL', 'HIGH') and e.epss >= 0.01 and f.fixed is not null then 'P2 crit/high, EPSS>=1%'
            when f.fixed is not null then 'P3 fixable, low likelihood'
            else 'P4 no fix available'
        end as tier
    from findings f left join kev k using (cve) left join epss e using (cve)
)
select tier, count(*) as findings, count(distinct cve) as distinct_cves, count(distinct image) as images,
       round(100.0 * count(*) / sum(count(*)) over (), 1) as pct_of_all
from tiered
group by 1 order by 1;
