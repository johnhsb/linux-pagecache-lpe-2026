# linux-pagecache-lpe-2026

**Copy Fail · Dirty Frag family** — a temporary mitigation script and response guide for 5 Linux kernel page-cache local privilege escalation (LPE) vulnerabilities disclosed in 2026 (CVE-2026-31431, CVE-2026-43284, CVE-2026-43500, CVE-2026-46300, CVE-2026-43503).

Documentation is available in two languages:

| | README | Technical guide |
|---|---|---|
| 🇰🇷 한국어 | [README.ko.md](README.ko.md) | [pagecache-lpe-guide.ko.md](pagecache-lpe-guide.ko.md) |
| 🇺🇸 English | [README.en.md](README.en.md) | [pagecache-lpe-guide.en.md](pagecache-lpe-guide.en.md) |

The mitigation script itself is [mitigate-cve-2026.sh](mitigate-cve-2026.sh):

```bash
sudo bash mitigate-cve-2026.sh --dry-run    # inspect only, no changes
sudo bash mitigate-cve-2026.sh              # interactive apply
sudo bash mitigate-cve-2026.sh --rollback   # revert if needed
```

License: [MIT](LICENSE). Provided AS IS — read the guide's prerequisites and limitations sections before applying to production.
