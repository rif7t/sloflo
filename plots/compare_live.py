"""Overlay live runs with and without the limiter, plus a per-phase table.

    python3 plots/compare_live.py --observe plots/live_step_observe [more repeats] \\
                                  --xdp plots/live_step_xdp [more repeats] \\
                                  [--out plots/compare_step]

Each prefix is the <prefix> of <prefix>.{trace,phases,requests}.csv. With
several repeats per mode, lines are the median across runs and the shaded band
is min..max. Writes <out>.png and <out>.md.
"""
import argparse

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ap = argparse.ArgumentParser()
ap.add_argument("--observe", nargs="+", required=True)
ap.add_argument("--xdp", nargs="+", required=True)
ap.add_argument("--out", default="plots/compare_step")
args = ap.parse_args()

FINE = 0.25  # seconds per bin for inflight / latency
COLORS = {"observe": "tab:red", "xdp": "tab:blue"}
LABELS = {"observe": "no limiter (observe-only)", "xdp": "with limiter (XDP)"}


def load(prefix):
    tr = pd.read_csv(prefix + ".trace.csv")
    ph = pd.read_csv(prefix + ".phases.csv")
    rq = pd.read_csv(prefix + ".requests.csv")
    t0 = ph.StartNs.min()
    tr["t"] = (tr.TimeStamp - t0) / 1e9
    rq["t"] = (rq.EndNs - t0) / 1e9
    rq["lat_ms"] = (rq.EndNs - rq.StartNs) / 1e6
    ph["t0"], ph["t1"] = (ph.StartNs - t0) / 1e9, (ph.EndNs - t0) / 1e9
    return tr, ph, rq


def binned(t, v, width, how, tmax):
    edges = np.arange(0, tmax + width, width)
    s = pd.Series(np.asarray(v, float), index=pd.cut(np.asarray(t), edges, include_lowest=True))
    g = s.groupby(level=0, observed=False)
    out = getattr(g, how)()
    out.index = edges[:-1]
    return out


def series(prefix, tmax):
    tr, ph, rq = load(prefix)
    ok, bad = rq[rq.Outcome == "ok"], rq[rq.Outcome != "ok"]
    return {
        "inflight": binned(tr.t, tr.Inflight, FINE, "max", tmax).ffill(),
        "limit": binned(tr.t, tr.ConcurrencyLimit, FINE, "last", tmax).ffill(),
        "latency": binned(tr.t, tr.LatestRTTNs / 1e6, FINE, "median", tmax).ffill(),
        "goodput": binned(ok.t, np.ones(len(ok)), 1.0, "sum", tmax).fillna(0),
        "failed": binned(bad.t, np.ones(len(bad)), 1.0, "sum", tmax).fillna(0),
    }, ph


runs = {m: [series(p, 55) for p in getattr(args, m)] for m in ("observe", "xdp")}
phases = runs["xdp"][0][1]


def band(ax, mode, key, **kw):
    df = pd.concat([r[0][key] for r in runs[mode]], axis=1)
    x = df.index.values
    ax.plot(x, df.median(axis=1), color=COLORS[mode], label=LABELS[mode], **kw)
    if df.shape[1] > 1:
        ax.fill_between(x, df.min(axis=1), df.max(axis=1), color=COLORS[mode], alpha=0.15, lw=0)


fig, ax = plt.subplots(4, 1, figsize=(11, 11), sharex=True)

ax[0].step(phases.t0.tolist() + [phases.t1.iloc[-1]], phases.Concurrency.tolist() + [phases.Concurrency.iloc[-1]],
           where="post", color="black", lw=1.5, label="offered concurrency")
for m in ("observe", "xdp"):
    band(ax[0], m, "inflight", lw=1.3)
df = pd.concat([r[0]["limit"] for r in runs["xdp"]], axis=1)
ax[0].step(df.index.values, df.median(axis=1), where="post", color="tab:blue", ls="--", lw=1, label="limit (XDP run)")
ax[0].axhline(150, color="gray", ls=":", lw=1)
ax[0].text(54.8, 160, "server capacity (150)", ha="right", fontsize=8, color="gray")
ax[0].set_ylabel("inflight requests")
ax[0].legend(loc="upper left", fontsize=8)

for m in ("observe", "xdp"):
    band(ax[1], m, "latency", lw=1.3)
ax[1].axhline(1000, color="gray", ls=":", lw=1)
ax[1].set_yscale("log")
ax[1].set_ylabel("server latency (ms)")
ax[1].legend(loc="upper left", fontsize=8)

for m in ("observe", "xdp"):
    band(ax[2], m, "goodput", lw=1.3)
ax[2].set_ylabel("successful requests / s")
ax[2].legend(loc="upper left", fontsize=8)

for m in ("observe", "xdp"):
    band(ax[3], m, "failed", lw=1.3)
ax[3].set_ylabel("failed / timed-out / s")
ax[3].set_xlabel("seconds since load start")
ax[3].legend(loc="upper left", fontsize=8)

for a in ax:
    a.grid(alpha=0.3)
    for _, p in phases.iterrows():
        if p.Phase % 2 == 0:
            a.axvspan(p.t0, p.t1, color="gray", alpha=0.07)
for _, p in phases.iterrows():
    ax[0].text((p.t0 + p.t1) / 2, 1.02, f"c={int(p.Concurrency)}", transform=ax[0].get_xaxis_transform(),
               ha="center", fontsize=9)
n_o, n_x = len(runs["observe"]), len(runs["xdp"])
ax[0].set_title(f"With vs without the limiter ({n_o} observe run{'s' * (n_o > 1)}, {n_x} XDP run{'s' * (n_x > 1)})", pad=24)
ax[3].set_xlim(0, 55)
fig.tight_layout()
fig.savefig(args.out + ".png", dpi=150)


# ---- per-phase table
def phase_stats(prefix):
    tr, ph, rq = load(prefix)
    rows = []
    for _, p in ph.iterrows():
        dur = p.t1 - p.t0
        r = rq[(rq.t >= p.t0) & (rq.t < p.t1)]
        ok = r[r.Outcome == "ok"]
        t = tr[(tr.t >= p.t0) & (tr.t < p.t1)]
        rows.append({
            "goodput": len(ok) / dur, "failed": (len(r) - len(ok)) / dur,
            "srv_p50": t.LatestRTTNs.median() / 1e6, "inflight_p50": t.Inflight.median(),
            "inflight_max": t.Inflight.max(), "limit_p50": t.ConcurrencyLimit.median(),
        })
    return pd.DataFrame(rows)


def agg(mode, key, fmt):
    d = np.array([phase_stats(p)[key].values for p in getattr(args, mode)])  # runs x phases
    med = np.median(d, axis=0)
    if d.shape[0] == 1:
        return [fmt.format(v) for v in med]
    return [f"{fmt.format(m)} ({fmt.format(lo)}–{fmt.format(hi)})" for m, lo, hi in zip(med, d.min(0), d.max(0))]


lines = ["| phase | metric | no limiter | with limiter |", "|---|---|---|---|"]
metrics = [("goodput", "goodput (req/s)", "{:.0f}"), ("failed", "failed (req/s)", "{:.0f}"),
           ("srv_p50", "server latency p50 (ms)", "{:.0f}"), ("inflight_p50", "inflight p50", "{:.0f}"),
           ("inflight_max", "inflight max", "{:.0f}")]
cols = {k: (agg("observe", k, f), agg("xdp", k, f)) for k, _, f in metrics}
limit = agg("xdp", "limit_p50", "{:.0f}")
for i, p in phases.iterrows():
    for j, (k, name, _) in enumerate(metrics):
        lines.append(f"| {'c=' + str(int(p.Concurrency)) if j == 0 else ''} | {name} | {cols[k][0][i]} | {cols[k][1][i]} |")
    lines.append(f"| | limit p50 | – | {limit[i]} |")
note = ("\nCompletions are attributed to the phase in which they finish, so the final c=20 phase includes "
        "requests draining from the c=800 backlog. Failures are client-side timeouts (5s) or connection errors; "
        "with the limiter on, most are SYNs shed at admission.\n")
open(args.out + ".md", "w").write("\n".join(lines) + "\n" + note)
print("\n".join(lines))
print("wrote", args.out + ".png,", args.out + ".md")
