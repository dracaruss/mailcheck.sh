# mailcheck.sh

A Bash script that audits a domain's DNS and email security posture passively. Built for fast external reconnaissance during authorized penetration tests, it prints a summary with a raw-evidence line under each check so results can be dropped straight into a report.

## Checks

- **SPF** - presence and policy strength (`-all` hardfail vs `~all` softfail vs `?all`/`+all`)
- **DMARC** - presence and published policy (`p=`)
- **DKIM** - sweeps common selectors and labels each by likely service (Microsoft 365, Postmark, KnowBe4, and others)
- **DNSSEC** - whether the zone is signed and validating
- **CAA** - which certificate authorities may issue for the domain
- **MTA-STS** and **TLS-RPT** - enforced-TLS and TLS-reporting policies for inbound mail
- **AXFR** - tests each nameserver for an open zone transfer

## Usage

```bash
chmod +x mailcheck.sh
./mailcheck.sh example.com
```

## Output

Each finding is color-coded: purple labels, a bold-red verdict, and a cyan `proof:` line showing the exact record or query result behind the verdict. The proof line makes screenshots self-evidencing for reporting.

## Requirements

`dig` (from `dnsutils` / `bind-tools`). No other dependencies.

## Notes

- The color codes render in the terminal only. Strip the escape sequences before pasting output into a report; screenshots keep the color.
- DKIM selector detection is best-effort. A selector name suggests but does not prove a given provider, and a domain may use a custom selector not on the common list.
- Run against the zone apex for DNSSEC, CAA, DMARC, and AXFR, since those live at the apex rather than on a subdomain.
- The AXFR test actively queries the target's nameservers. Only run it against systems within your authorized engagement scope.

## Disclaimer

_For use only against domains you own or are explicitly authorized to test._
