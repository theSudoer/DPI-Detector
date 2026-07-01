# DPI-Detector

DPI Detector, this is for educational purposes only, I am not liable for anything when running this program.

## What it does

Runs a batch of independent network signals against a list of sites (DNS
consistency, TLS certificate/chain checks, TLS timing, TCP RST injection,
TTL/traceroute, packet fragmentation, JA3/JA3S, ASN/geolocation, QUIC) and
combines the scores into a per-site "suspicious" verdict plus an overall
DPI/censorship conclusion.

## Dependencies

The core script only needs the Python standard library. Everything else is
optional — a missing package just disables that one detector instead of
crashing:

| Package | Enables |
|---|---|
| `requests` | CT log lookup, HTTP header/captive-portal check, VPN external-IP check, ASN/geolocation, censorship check |
| `dnspython` | Public-resolver DNS check (`dns.resolver`) |
| `cryptography` | Certificate key-size inspection |
| `psutil` | VPN interface/process detection |
| `scapy` | TCP RST injection, TTL/traceroute, packet fragmentation, and the scapy-based JA3/JA3S fallback. Needs raw-socket privileges (root on Linux/macOS, admin + [Npcap](https://npcap.com/) on Windows) — without both, these checks report an error and contribute nothing to the score. |
| `aioquic` | QUIC/HTTP3 probe |
| `ja3python` | Preferred JA3/JA3S extraction path (used instead of the scapy fallback when both scapy and ja3python are available) |

Install whichever of these you want with `pip install requests dnspython
cryptography psutil scapy aioquic ja3python`.

## Accuracy notes / known limitations

This is a heuristic tool, not a calibrated classifier — there's no
ground-truth dataset behind the scoring weights, so treat the verdict as a
prompt to investigate further, not a definitive result. Some things worth
knowing:

- **CDN/anycast hostnames legitimately resolve differently per resolver.**
  The DNS-consistency check recognizes common CDN hostnames (Cloudflare,
  Google, Akamai, AWS, etc.) and doesn't score a resolver mismatch for them,
  but non-CDN sites can still occasionally show benign resolver differences.
- **TLS timing is judged relative to the other sites in the same run**, not
  against a fixed threshold, so it adapts to your own baseline latency
  (mobile, satellite, distant server) instead of flagging every slow
  connection. It needs at least 3 sites in one run to produce a signal.
- **Certificate trust relies on the OS trust store**, not a hardcoded CA
  list — a cert is only flagged if the TLS handshake's own chain
  verification failed.
- **The JA3/JA3S known-bad-hash check fingerprints your own outbound TLS
  client**, not the network path. A match tells you your local TLS stack's
  fingerprint collides with a known malware/Tor fingerprint — it isn't by
  itself evidence of interception.
- **Raw-socket checks (RST injection, TTL, fragmentation) need scapy +
  root/admin privileges.** Without them they report an error rather than a
  false "clean" result, but they also can't contribute any signal.
