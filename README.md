# Cybersecurity Daily Briefing

Sends a daily HTML email with:
- **CISA Known Exploited Vulnerabilities** added in the last 24 hours
- **Top 10 new CVEs** from NVD, sorted by CVSS score
- **Latest headlines** from Krebs, BleepingComputer, SANS ISC, The Hacker News, Dark Reading

Runs free via GitHub Actions on a daily cron schedule.

## Setup

### 1. Create a GitHub repository

Push this folder to a new GitHub repo (can be private).

### 2. Get a SendGrid API key

1. Sign up at [sendgrid.com](https://sendgrid.com) (free tier: 100 emails/day)
2. Go to **Settings → API Keys → Create API Key**
3. Choose **Restricted Access** → enable **Mail Send**
4. Copy the key

### 3. Verify your sender email in SendGrid

Go to **Settings → Sender Authentication** and verify the `FROM_EMAIL` address.

### 4. Add GitHub secrets

In your repo: **Settings → Secrets and variables → Actions → New repository secret**

| Secret name | Value |
|---|---|
| `SENDGRID_API_KEY` | Your SendGrid API key |
| `TO_EMAIL` | Your email address (where to receive the briefing) |
| `FROM_EMAIL` | Verified sender address in SendGrid |
| `ANTHROPIC_API_KEY` | Your Anthropic API key (for the Claude CISO executive summary) |

### 5. Adjust the schedule (optional)

Edit `.github/workflows/daily_briefing.yml` and change the cron expression:

```yaml
- cron: "0 7 * * *"   # 07:00 UTC daily
```

Use [crontab.guru](https://crontab.guru) to build your preferred schedule.

### 6. Test it manually

Once the repo is pushed, go to **Actions → Daily Cybersecurity Briefing → Run workflow**.

## Local testing

```bash
pip install -r requirements.txt
export SENDGRID_API_KEY=your_key
export TO_EMAIL=you@example.com
export FROM_EMAIL=verified@example.com
python briefing.py
```
