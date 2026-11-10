# Agent Notes

## Production RPZ troubleshooting

- DNS RCODE 5 is `REFUSED`. For the production RPZ `trustpositifkominfo.` at master `103.155.190.72:53`, SOA queries have returned authoritative `NOERROR`, while direct AXFR and IXFR probes returned `REFUSED`. The panel's observed public egress IP during the check was `103.155.191.245`; the upstream had no TSIG key configured.
- This indicates the master is reachable and serves the zone SOA, but its transfer policy refuses transfers. It is not a local AXFR/IXFR parsing or CDB build failure. Confirm current values before acting because the panel egress IP or master policy can change.
- Remediation must be made on the master side: allow zone transfer for `trustpositifkominfo.` from the panel's current egress IP, or configure a valid TSIG key and permit transfers using it. Then retry **Sync** in the panel and confirm serial/domain count and `last_error`.
- On any transfer error, the RPZ sync implementation records `last_error` and preserves the existing source content/serial rather than replacing it with a failed or partial transfer. Check whether the paired RPZ source is enabled before expecting that data to appear in a build.
- Do not restart or enable `dnsdist` as part of RPZ transfer troubleshooting; the transfer is performed by the panel service.
