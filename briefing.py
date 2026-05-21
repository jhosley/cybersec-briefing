#!/usr/bin/env python3
"""Daily cybersecurity briefing — fetches RSS, NVD CVEs, and CISA KEV, then emails a summary."""

import datetime
import os
import textwrap

import anthropic
import feedparser
import requests
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

SENDGRID_API_KEY = os.environ["SENDGRID_API_KEY"]
TO_EMAIL = os.environ["TO_EMAIL"]
FROM_EMAIL = os.environ["FROM_EMAIL"]
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
BRIEFING_HOUR_UTC = int(os.environ.get("BRIEFING_HOUR_UTC", "7"))

RSS_FEEDS = [
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed_full.xml"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
]

MAX_RSS_ITEMS = 5
MAX_CVES = 10
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0


# ---------------------------------------------------------------------------
# Data fetchers
# ---------------------------------------------------------------------------

def fetch_rss(name: str, url: str) -> list[dict]:
    try:
        feed = feedparser.parse(url)
        items = []
        for entry in feed.entries[:MAX_RSS_ITEMS]:
            summary = entry.get("summary", "")
            # Strip HTML tags crudely for plain preview
            import re
            summary = re.sub(r"<[^>]+>", "", summary).strip()
            summary = " ".join(summary.split())[:300]
            items.append({
                "title": entry.get("title", "(no title)").strip(),
                "link": entry.get("link", ""),
                "summary": summary,
                "published": entry.get("published", ""),
            })
        return items
    except Exception as exc:
        print(f"[WARN] RSS fetch failed for {name}: {exc}")
        return []


def fetch_nvd_cves(hours_back: int = 24) -> list[dict]:
    end = datetime.datetime.utcnow()
    start = end - datetime.timedelta(hours=hours_back)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 20,
    }
    try:
        r = requests.get(url, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        print(f"[WARN] NVD fetch failed: {exc}")
        return []

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln["cve"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "No description available.",
        )
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break
        cves.append({
            "id": cve["id"],
            "description": desc[:400],
            "cvss": cvss_score,
            "severity": severity,
            "published": cve.get("published", ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        })

    cves.sort(key=lambda x: x["cvss"] or 0, reverse=True)
    return cves[:MAX_CVES]


def fetch_cisa_kev(days_back: int = 1) -> list[dict]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        print(f"[WARN] CISA KEV fetch failed: {exc}")
        return []

    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days_back)).strftime("%Y-%m-%d")
    recent = [v for v in data.get("vulnerabilities", []) if v.get("dateAdded", "") >= cutoff]
    recent.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    return recent[:15]


# ---------------------------------------------------------------------------
# Claude executive summary
# ---------------------------------------------------------------------------

_CISO_SYSTEM_PROMPT = """\
You are a senior threat intelligence analyst briefing the CISO of a large international \
telecommunications company. Your audience is a seasoned executive who manages risk for a \
carrier operating mobile, fixed-line, and wholesale networks across multiple continents, \
with deep exposure to SS7/Diameter interconnect abuse, OT/ICS infrastructure, supply chain \
risks in network equipment (RAN, core, OSS/BSS), nation-state actors targeting critical \
infrastructure, and regulatory obligations across jurisdictions (FCC, GDPR, NIS2, OFCOM).

Write concisely. Lead with the most operationally relevant findings. Flag anything that:
- Directly threatens telecom protocols (SS7, Diameter, GTP, SIP, ISUP, BGP)
- Affects network equipment vendors (Ericsson, Nokia, Huawei, Cisco, Juniper, etc.)
- Is actively exploited by nation-state or ransomware actors targeting carriers
- Has regulatory or compliance implications for a global telecom operator
- Affects OT/SCADA systems relevant to data centers or network infrastructure

Structure your response as four clearly labeled sections:
0. **BLUF** — 2–3 sentences of pure narrative. Answer one question: "How should I think \
about today's threat landscape?" Give the mental frame — the pattern, the trend, the \
posture. No bullets. Write it as if you're handing the CISO a single thought to carry \
into their morning.
1. **EXECUTIVE SUMMARY** — 3–5 sentences, the single most important risk picture today
2. **KEY THREATS FOR TELECOM** — bullet list of 3–6 items most relevant to our environment
3. **RECOMMENDED ACTIONS** — bullet list of 2–4 concrete, actionable next steps for today

Tone: direct, no filler, no pleasantries. Write as if this will be read in 90 seconds \
between executive meetings.\
"""


def generate_executive_summary(
    cves: list[dict],
    kev: list[dict],
    rss_data: list[tuple[str, list[dict]]],
) -> str:
    if not ANTHROPIC_API_KEY:
        return ""

    # Build a compact plaintext digest to feed Claude
    lines = []

    if kev:
        lines.append("=== CISA KNOWN EXPLOITED VULNERABILITIES (NEW TODAY) ===")
        for v in kev:
            lines.append(
                f"- {v.get('cveID','')} | {v.get('vendorProject','')} {v.get('product','')} | "
                f"{v.get('vulnerabilityName','')} | Due: {v.get('dueDate','')}"
            )

    if cves:
        lines.append("\n=== TOP NEW CVEs BY CVSS (LAST 24 HOURS) ===")
        for c in cves:
            score = f"{c['cvss']:.1f}" if c["cvss"] else "N/A"
            lines.append(f"- {c['id']} [{c['severity']} {score}] — {c['description'][:200]}")

    lines.append("\n=== NEWS HEADLINES ===")
    for feed_name, items in rss_data:
        for item in items:
            lines.append(f"- [{feed_name}] {item['title']}")

    digest = "\n".join(lines)

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=1200,
            thinking={"type": "adaptive"},
            system=[
                {
                    "type": "text",
                    "text": _CISO_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Today's threat intelligence digest:\n\n{digest}\n\n"
                        "Produce your CISO briefing now."
                    ),
                }
            ],
        )
        full_text = "\n".join(
            block.text for block in response.content if block.type == "text"
        ).strip()
        print(f"[DEBUG] Claude raw output:\n{full_text[:800]}")

        # Split BLUF from the rest — robust to numbering variants like "**0. BLUF**"
        import re
        sections = re.split(r'\n(?=\*\*)', full_text)
        bluf = ""
        rest_sections = []
        for section in sections:
            if re.match(r'\*\*(?:\d+\.\s*)?BLUF\*\*', section, re.IGNORECASE):
                bluf = re.sub(r'\*\*(?:\d+\.\s*)?BLUF\*\*[:\s\-—]*\n*', '', section, flags=re.IGNORECASE).strip()
            else:
                rest_sections.append(section)
        rest = "\n".join(rest_sections).strip()
        return bluf, rest
    except Exception as exc:
        print(f"[WARN] Claude summary failed: {exc}")
        return "", ""


def _markdown_to_html(text: str) -> str:
    """Convert the minimal markdown Claude uses (bold, bullets) to inline HTML."""
    import re
    lines = text.split("\n")
    html_lines = []
    for line in lines:
        # Section headers like **EXECUTIVE SUMMARY**
        line = re.sub(r"^\*\*(.+?)\*\*$", r"<strong>\1</strong>", line)
        # Inline bold
        line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
        # Bullet points
        if line.startswith("- "):
            line = f'<li style="margin:3px 0;">{line[2:]}</li>'
        elif line == "":
            line = "<br>"
        html_lines.append(line)
    # Wrap consecutive <li> in <ul>
    result = "\n".join(html_lines)
    result = re.sub(r"((?:<li[^>]*>.*?</li>\n?)+)", r"<ul style='margin:6px 0;padding-left:20px;'>\1</ul>", result)
    return result


# ---------------------------------------------------------------------------
# HTML email builder
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f39c12",
    "LOW": "#27ae60",
    "UNKNOWN": "#7f8c8d",
}


def severity_badge(severity: str, score: float | None) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), "#7f8c8d")
    label = f"{severity}"
    if score is not None:
        label += f" {score:.1f}"
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:11px;font-weight:bold;">{label}</span>'
    )


def section_header(title: str) -> str:
    return (
        f'<tr><td style="padding:24px 0 8px 0;">'
        f'<h2 style="margin:0;font-size:18px;color:#1a1a2e;border-bottom:2px solid #3498db;'
        f'padding-bottom:6px;">{title}</h2></td></tr>'
    )


def build_html(
    date_str: str,
    rss_data: list[tuple[str, list[dict]]],
    cves: list[dict],
    kev: list[dict],
    bluf: str = "",
    executive_summary: str = "",
) -> str:
    critical_count = sum(1 for c in cves if (c["cvss"] or 0) >= CVSS_CRITICAL_THRESHOLD)
    high_count = sum(1 for c in cves if CVSS_HIGH_THRESHOLD <= (c["cvss"] or 0) < CVSS_CRITICAL_THRESHOLD)
    kev_count = len(kev)

    # Build BLUF block — sits between header and stats bar
    bluf_block = ""
    if bluf:
        bluf_block = f"""
        <!-- BLUF -->
        <tr><td style="background:#0f3460;padding:20px 40px 18px 40px;
                        border-bottom:1px solid #1a4a7a;">
          <p style="margin:0;color:#ffffff;font-size:15px;line-height:1.75;
                    font-style:italic;letter-spacing:0.1px;">
            {bluf}
          </p>
        </td></tr>"""

    # Build Claude executive summary block
    summary_block = ""
    if executive_summary:
        summary_html = _markdown_to_html(executive_summary)
        summary_block = f"""
        <!-- Claude Executive Summary -->
        <tr><td style="background:#1a1a2e;padding:24px 40px;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td>
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
                <span style="font-size:18px;">&#129302;</span>
                <span style="color:#a0b4c8;font-size:11px;text-transform:uppercase;
                             letter-spacing:2px;font-weight:600;">AI-Powered CISO Briefing</span>
              </div>
              <div style="color:#e8eaf0;font-size:14px;line-height:1.7;">
                {summary_html}
              </div>
            </td></tr>
          </table>
        </td></tr>"""

    # Build RSS rows
    rss_rows = ""
    for feed_name, items in rss_data:
        if not items:
            continue
        rss_rows += f"""
        <tr><td style="padding:16px 0 4px 0;">
          <h3 style="margin:0;font-size:14px;color:#2c3e50;text-transform:uppercase;
                     letter-spacing:1px;">{feed_name}</h3>
        </td></tr>"""
        for item in items:
            rss_rows += f"""
        <tr><td style="padding:6px 0 10px 12px;border-left:3px solid #3498db;">
          <a href="{item['link']}" style="color:#2980b9;text-decoration:none;font-weight:bold;
                                          font-size:14px;">{item['title']}</a>
          <div style="color:#7f8c8d;font-size:12px;margin-top:2px;">{item['published']}</div>
          {"<div style='color:#555;font-size:13px;margin-top:4px;'>" + item['summary'] + "...</div>" if item['summary'] else ""}
        </td></tr>"""

    # Build CVE rows
    cve_rows = ""
    if cves:
        for cve in cves:
            badge = severity_badge(cve["severity"], cve["cvss"])
            cve_rows += f"""
        <tr><td style="padding:8px 0;border-bottom:1px solid #ecf0f1;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
            <a href="{cve['url']}" style="color:#2980b9;font-weight:bold;
                                          text-decoration:none;">{cve['id']}</a>
            &nbsp;{badge}
          </div>
          <div style="color:#555;font-size:13px;">{cve['description']}</div>
        </td></tr>"""
    else:
        cve_rows = '<tr><td style="color:#7f8c8d;font-style:italic;">No new CVEs published in the last 24 hours.</td></tr>'

    # Build KEV rows
    kev_rows = ""
    if kev:
        for v in kev:
            kev_rows += f"""
        <tr><td style="padding:8px 0;border-bottom:1px solid #ecf0f1;">
          <div style="margin-bottom:4px;">
            <a href="https://nvd.nist.gov/vuln/detail/{v.get('cveID','')}"
               style="color:#c0392b;font-weight:bold;text-decoration:none;">{v.get('cveID','')}</a>
            <span style="color:#7f8c8d;font-size:12px;margin-left:8px;">Added {v.get('dateAdded','')}</span>
          </div>
          <div style="font-size:13px;color:#2c3e50;font-weight:600;">{v.get('product','')}</div>
          <div style="font-size:13px;color:#555;">{v.get('vulnerabilityName','')}</div>
          {"<div style='font-size:12px;color:#e74c3c;margin-top:3px;'>Due: " + v.get('dueDate','') + "</div>" if v.get('dueDate') else ""}
        </td></tr>"""
    else:
        kev_rows = '<tr><td style="color:#7f8c8d;font-style:italic;">No new CISA KEV additions today.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f5f6fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f6fa;padding:24px 0;">
    <tr><td align="center">
      <table width="640" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:8px;overflow:hidden;
                    box-shadow:0 2px 8px rgba(0,0,0,0.08);">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);
                        padding:32px 40px;">
          <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:700;">
            Cybersecurity Daily Briefing
          </h1>
          <p style="margin:8px 0 0 0;color:#a0b4c8;font-size:14px;">{date_str}</p>
        </td></tr>

        {bluf_block}

        <!-- Summary bar -->
        <tr><td style="background:#eaf0fb;padding:16px 40px;border-bottom:1px solid #d6e4f0;">
          <table width="100%" cellpadding="0" cellspacing="0"><tr>
            <td style="text-align:center;">
              <div style="font-size:28px;font-weight:700;color:#c0392b;">{critical_count}</div>
              <div style="font-size:11px;color:#7f8c8d;text-transform:uppercase;">Critical CVEs</div>
            </td>
            <td style="text-align:center;">
              <div style="font-size:28px;font-weight:700;color:#e67e22;">{high_count}</div>
              <div style="font-size:11px;color:#7f8c8d;text-transform:uppercase;">High CVEs</div>
            </td>
            <td style="text-align:center;">
              <div style="font-size:28px;font-weight:700;color:#8e44ad;">{kev_count}</div>
              <div style="font-size:11px;color:#7f8c8d;text-transform:uppercase;">CISA KEV Additions</div>
            </td>
            <td style="text-align:center;">
              <div style="font-size:28px;font-weight:700;color:#2980b9;">{sum(len(i) for _, i in rss_data)}</div>
              <div style="font-size:11px;color:#7f8c8d;text-transform:uppercase;">News Items</div>
            </td>
          </tr></table>
        </td></tr>

        {summary_block}

        <!-- Body -->
        <tr><td style="padding:0 40px 32px 40px;">
          <table width="100%" cellpadding="0" cellspacing="0">

            {section_header("&#128204; CISA Known Exploited Vulnerabilities")}
            {kev_rows}

            {section_header("&#128679; New CVEs (Last 24h, by Severity)")}
            {cve_rows}

            {section_header("&#128240; Cybersecurity News")}
            {rss_rows}

          </table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background:#f8f9fa;padding:16px 40px;border-top:1px solid #ecf0f1;
                        text-align:center;">
          <p style="margin:0;font-size:11px;color:#bdc3c7;">
            Sources: CISA KEV &bull; NIST NVD &bull; Krebs on Security &bull; BleepingComputer
            &bull; SANS ISC &bull; The Hacker News &bull; Dark Reading
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Email sender
# ---------------------------------------------------------------------------

def send_email(subject: str, html_content: str) -> None:
    sg = SendGridAPIClient(SENDGRID_API_KEY)
    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=TO_EMAIL,
        subject=subject,
        html_content=html_content,
    )
    response = sg.send(message)
    print(f"Email sent — status {response.status_code}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    today = datetime.datetime.utcnow()
    date_str = today.strftime("%A, %B %-d, %Y — %H:%M UTC")
    print(f"Building briefing for {date_str}")

    print("Fetching RSS feeds...")
    rss_data = [(name, fetch_rss(name, url)) for name, url in RSS_FEEDS]

    print("Fetching NVD CVEs...")
    cves = fetch_nvd_cves(hours_back=24)
    print(f"  {len(cves)} CVEs retrieved")

    print("Fetching CISA KEV...")
    kev = fetch_cisa_kev(days_back=1)
    print(f"  {len(kev)} KEV additions today")

    print("Generating Claude executive summary...")
    bluf, executive_summary = generate_executive_summary(cves, kev, rss_data)
    if bluf or executive_summary:
        print("  Summary generated.")
    else:
        print("  Skipped (no API key or error).")

    html = build_html(date_str, rss_data, cves, kev, bluf, executive_summary)

    subject = f"[CyberBrief] {today.strftime('%Y-%m-%d')} — {len(kev)} KEV | {sum(1 for c in cves if (c['cvss'] or 0) >= CVSS_CRITICAL_THRESHOLD)} Critical CVEs"
    print(f"Sending: {subject}")
    send_email(subject, html)
    print("Done.")


if __name__ == "__main__":
    main()
