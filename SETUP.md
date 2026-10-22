# Connecting LMS to Claude

Ask Claude about TransBnk LMS — bank balances, transactions, account summaries — in
plain language. Read-only: nothing here can move money or change data.

Each person signs in with **their own** TransBnk credentials and sees only the
entities and programs they're entitled to. Nobody shares a token.

---

## 1. Add the connector

In Claude, open **Settings → Connectors → Add custom connector** and enter the
connector URL your TransBnk admin gave you (it ends in `/mcp`).

## 2. Sign in

Click **Connect**. Claude opens TrustHub's sign-in page in your browser; sign in
there as usual. Your password goes only to TrustHub — never to lms-mcp or Claude.

## 3. Check it works

The tools appear under the tools icon in the message box. Try:

> what are my bank balances?

## What you can ask

| Ask | |
|---|---|
| "what are my bank balances?" | per account, grouped by bank, with how fresh each is |
| "which accounts do we have at HDFC?" | account list and metadata |
| "show transactions from 1 Aug to 21 Sep" | the transaction feed |
| "credit and debit totals per account last month" | per-account rollup |
| "daily credit vs debit for September" | daily series |
| "give me the overall dashboard numbers" | headline totals |

### Two things that will look odd but are correct

**Balances often read "total across 1 of 15 accounts".** A balance is a snapshot taken
when someone last fetched it from the bank, and most accounts have never been fetched.
Rather than add up numbers of different ages, the tool totals only the current ones and
tells you what that covers. A single confident number would be misleading.

**If you have more than one entity or program, Claude will ask which one** before
answering, because they're separate books. Say which, or ask for all of them combined.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "not signed in" / "reconnect the connector" | Your sign-in expired; disconnect and reconnect the connector. |
| "no entity/program scopes - refusing to start" | Your account isn't entitled to any program; ask your TransBnk admin. |

## What it can and can't do

**Can:** read accounts, balances, transactions, summaries, dashboard totals — for the
entities and programs your login is entitled to.

**Can't:** move money, change any record, trigger a balance refresh, or reach another
tenant's data. Tenant identity comes from your login, not from anything Claude types,
so it cannot be talked into reading someone else's accounts.
