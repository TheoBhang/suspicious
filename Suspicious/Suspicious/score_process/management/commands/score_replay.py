"""Replay the live scoring path on stored cases, keep nothing, and compare."""
import csv

from django.core.management.base import BaseCommand

from case_handler.models import Case
from score_process import replay


def _pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def _rate_line(label, r):
    return (f"  {label}: {r['k']}/{r['n']} = {_pct(r['rate'])}"
            f" (95% CI {_pct(r['lo'])} to {_pct(r['hi'])})")


class Command(BaseCommand):
    help = (
        "Replay the live scoring path on stored cases inside a rolled-back transaction. Two views: "
        "Drift (stored verdict vs replay, analyst-edited cases excluded: the upgrade check) and "
        "Accuracy (analyst verdict from the label ledger vs replay: missed threats and false "
        "alarms). Run it on a restored copy of the database, not on live production."
    )

    def add_arguments(self, parser):
        parser.add_argument("--road", choices=["mail", "ioc", "file", "all"], default="all")
        parser.add_argument("--limit", type=int, default=0, help="Newest N cases only.")
        parser.add_argument("--case", type=int, action="append", help="Only this case id (repeatable).")
        parser.add_argument("--csv", help="Write every disagreement to this file.")

    def handle(self, *args, **opts):
        ids = Case.objects.exclude(results="").order_by("-id")
        if opts["case"]:
            ids = ids.filter(id__in=opts["case"])
        ids = list(ids.values_list("id", flat=True))
        if opts["limit"]:
            ids = ids[: opts["limit"]]
        labels = replay.analyst_labels()
        rows = [replay.replay_case(i, labels.get(i)) for i in ids]
        if opts["road"] != "all":
            rows = [r for r in rows if r.road == opts["road"]]

        self.report("All roads", rows)
        for road in sorted({r.road for r in rows}):
            if opts["road"] == "all" and len({r.road for r in rows}) > 1:
                self.report(f"Road: {road}", [r for r in rows if r.road == road])
        if opts["csv"]:
            self.write_csv(opts["csv"], rows)

    def report(self, title, rows):
        s = replay.summarise(rows)
        w = self.stdout.write
        w(f"\n=== {title}: {len(rows)} cases, {s['errors']} scoring errors ===")
        if s["no_ai"]:
            w(f"{s['no_ai']} mail cases have no AI assessment (finalised before the ai_model connector): "
              "left out of both views, because a missing AI vote is Inconclusive by design now")
        d = s["drift"]
        w(f"Drift (stored vs replay, analyst-edited excluded): {d['changed']} of {d['n']} changed")
        for (old, new), n in sorted(d["matrix"].items(), key=lambda x: str(x)):
            w(f"  {old} -> {new}: {n}{'' if old == new else '  <-- CHANGED'}")
        a = s["accuracy"]
        w(f"Accuracy (analyst verdict vs replay): {a['agree']} of {a['n']} agree")
        for (old, new), n in sorted(a["matrix"].items(), key=lambda x: str(x)):
            w(f"  analyst {old} -> replay {new}: {n}")
        w(_rate_line("Missed threats (analyst Dangerous, replay Safe)", a["missed_threat"]))
        w(_rate_line("False alarms (analyst Safe, replay Dangerous)", a["false_alarm"]))

    def write_csv(self, path, rows):
        with open(path, "w", newline="") as fh:
            out = csv.writer(fh)
            out.writerow(["case_id", "road", "kind", "stored", "analyst", "replay", "score", "error"])
            for r in rows:
                if r.ai is False and not r.error:
                    continue
                kind = "accuracy" if r.analyst else "drift"
                expected = r.analyst or r.stored
                if r.error or r.replay != expected:
                    out.writerow([r.case_id, r.road, kind, r.stored, r.analyst or "",
                                  r.replay or "", r.score if r.score is not None else "", r.error or ""])
        self.stdout.write(f"\nDisagreements written to {path}")
