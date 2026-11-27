# Challenge triage

When a reporter challenges a verdict, a fixed set of rules decides whether the challenge needs a
TheHive alert now (`ALERT`) or can wait in the analysts' queue (`ANALYST`). No model is involved.
Every decision is stored (`ChallengeTriage`: decision, reason code, rule-set version, the facts
used, the mode, and whether it was acted on), readable from the database or the Django shell.

## Mode

`integrations.thehive.challenge_triage` in `settings.json`:

| Value | Effect |
|---|---|
| `log` (default) | Decide and record; the alert goes out exactly as before. Use it to see what `enforce` would do. |
| `enforce` | An `ANALYST` decision sends no TheHive alert (nor the CERT mail when TheHive is off). The case stays Contested and visible in Investigations. |
| `off` | No triage. |

A failure in the triage never blocks the alert.

## Rules (first match wins)

| # | Rule | Decision | Reason code |
|---|---|---|---|
| 1 | The reason says the reporter clicked, opened, entered credentials, downloaded, installed or paid (English or French words; a negated sentence matches too) | ALERT | `compromise-claimed` |
| 2 | The case verdict is Dangerous | ALERT | `case-dangerous` |
| 3 | A member of the case's campaign is Dangerous | ALERT | `campaign-dangerous` |
| 4 | The case is on the denylist | ALERT | `denylisted` |
| 5 | The reporter says Safe and the verdict is Safe, Inconclusive or Suspicious | ANALYST | `reporter-false-positive` |
| 6 | The reporter says Dangerous and the verdict is Suspicious | ALERT | `missed-threat-corroborated` |
| 7 | The reporter says Dangerous and the verdict is Safe or Inconclusive | ANALYST | `missed-threat-uncorroborated` |
| 8 | Anything else | ALERT | `no-rule-matched` |

Only an explicit rule can say `ANALYST`; an unmatched case alerts, as every challenge did before.
The reporter's text is untrusted: it can only raise an alert (rule 1), never remove one.

## Before switching to `enforce`

Let `log` run, then compare the `ANALYST` rows with what analysts did with those challenges. The
exit criterion should be numeric and agreed first, for example no `ANALYST` row where an analyst
raised an alert, over a fixed number of weeks. Not built: rules on earlier challenges of the same
campaign, on MISP hits and on a model's reading of the reason text (see
`docs/plans/ai-system1-backlog.md`, H2).
