"""Plot a live run: offered load vs what the limiter did.

    python3 plots/plot_live.py plots/live_step_xdp [more prefixes to compare...]

Reads <prefix>.trace.csv, .phases.csv, .requests.csv; writes <prefix>.png.
"""
import sys

import matplotlib.pyplot as plt
import pandas as pd

BIN = "100ms"


def load(prefix):
    tr = pd.read_csv(prefix + ".trace.csv")
    ph = pd.read_csv(prefix + ".phases.csv")
    rq = pd.read_csv(prefix + ".requests.csv")
    t0 = ph.StartNs.min()
    tr["t"] = (tr.TimeStamp - t0) / 1e9
    ph["t0"], ph["t1"] = (ph.StartNs - t0) / 1e9, (ph.EndNs - t0) / 1e9
    rq["t"] = (rq.EndNs - t0) / 1e9
    tr = tr[(tr.t >= -1) & (tr.t <= ph.t1.max() + 1)]
    idx = lambda d: pd.to_timedelta(d.t, unit="s")
    b = tr.set_index(idx(tr)).resample(BIN)
    trb = pd.DataFrame({
        "rtt": b.LatestRTTNs.median() / 1e6,
        "minrtt": b.MinRTTNs.min() / 1e6,
        "grad": b.Gradient.mean(),
        "grad_min": b.Gradient.min(),
        "limit": b.ConcurrencyLimit.last(),
        "inflight": b.Inflight.max(),
    }).ffill()
    trb.index = trb.index.total_seconds()
    rb = rq.set_index(idx(rq)).resample("1s")
    rqb = pd.DataFrame({
        "ok": rb.Outcome.apply(lambda x: (x == "ok").sum()),
        "failed": rb.Outcome.apply(lambda x: (x != "ok").sum()),
    })
    rqb.index = rqb.index.total_seconds()
    ok = rq[rq.Outcome == "ok"].copy()
    ok["lat"] = (ok.EndNs - ok.StartNs) / 1e6
    g = ok.set_index(idx(ok)).resample("1s").lat
    lat = pd.DataFrame({"p50": g.median(), "p95": g.quantile(0.95)})
    lat.index = lat.index.total_seconds()
    return trb, ph, rqb, lat


def draw(prefix):
    trb, ph, rqb, lat = load(prefix)
    fig, ax = plt.subplots(5, 1, figsize=(11, 12), sharex=True)

    ax[0].step(ph.t0.tolist() + [ph.t1.iloc[-1]], ph.Concurrency.tolist() + [ph.Concurrency.iloc[-1]],
               where="post", color="black", label="offered concurrency")
    ax[0].plot(trb.index, trb.inflight, color="tab:blue", lw=1, label="inflight requests (kernel)")
    ax[0].step(trb.index, trb.limit, where="post", color="tab:red", label="concurrency limit")
    ax[0].set_ylabel("requests")
    ax[0].legend(loc="upper left", fontsize=8)

    ax[1].plot(trb.index, trb.rtt, color="tab:blue", label="app latency (bin median)")
    ax[1].plot(trb.index, trb.minrtt, color="tab:orange", label="window minRTT (bin min)")
    ax[1].set_ylabel("server latency (ms)")
    ax[1].set_yscale("log")
    ax[1].legend(loc="upper left", fontsize=8)

    ax[2].plot(trb.index, trb.grad, color="tab:green", label="mean")
    ax[2].plot(trb.index, trb.grad_min, color="tab:green", alpha=0.4, label="min")
    ax[2].set_ylabel("gradient")
    ax[2].legend(loc="lower left", fontsize=8)

    ax[3].plot(lat.index, lat.p50, color="tab:blue", label="p50")
    ax[3].plot(lat.index, lat.p95, color="tab:purple", label="p95")
    ax[3].set_ylabel("client latency (ms)\n(ok requests)")
    ax[3].legend(loc="upper left", fontsize=8)

    ax[4].bar(rqb.index, rqb.ok, width=1.0, align="edge", color="tab:green", label="ok")
    ax[4].bar(rqb.index, rqb.failed, width=1.0, align="edge", bottom=rqb.ok, color="tab:red", label="failed/timeout")
    ax[4].set_ylabel("requests completed / s")
    ax[4].set_xlabel("seconds since load start")
    ax[4].legend(loc="upper left", fontsize=8)

    for a in ax:
        a.grid(alpha=0.3)
        for _, p in ph.iterrows():
            if p.Phase % 2 == 0:
                a.axvspan(p.t0, p.t1, color="gray", alpha=0.07)
    for _, p in ph.iterrows():
        ax[0].text((p.t0 + p.t1) / 2, 1.02, f"c={int(p.Concurrency)}", transform=ax[0].get_xaxis_transform(),
                   ha="center", fontsize=8)
    ax[0].set_title(prefix.split("/")[-1], pad=22)
    ax[4].set_xlim(0, ph.t1.max())
    fig.tight_layout()
    out = prefix + ".png"
    fig.savefig(out, dpi=150)
    print("wrote", out)


for p in sys.argv[1:]:
    draw(p)
