"""Plot the window-reset trace produced by:
    go test ./internal/control -window-csv=plots/window_reset_trace.csv
"""
import sys

import matplotlib.pyplot as plt
import pandas as pd

src = sys.argv[1] if len(sys.argv) > 1 else "plots/window_reset_trace.csv"
out = sys.argv[2] if len(sys.argv) > 2 else "plots/window_reset_trace.png"
df = pd.read_csv(src)
t = df.ElapsedNs / 1e6  # ms
resets = df[df.WindowReset]

fig, ax = plt.subplots(3, 1, figsize=(10, 8), sharex=True)

ax[0].plot(t, df.RTTNs / 1e3, "o-", label="RTT")
ax[0].step(t, df.NewMinRTTNs / 1e3, where="post", label="window minRTT")
ax[0].set_ylabel("µs")
ax[0].legend()

ax[1].plot(t, df.Gradient, "o-", color="tab:green")
ax[1].set_ylabel("gradient (minRTT / RTT)")

ax[2].step(t, df.NewConcurrencyLimit, where="post", color="tab:red")
ax[2].set_ylabel("concurrency limit")
ax[2].set_xlabel("elapsed (ms)")

for a in ax:
    for x in resets.ElapsedNs / 1e6:
        a.axvline(x, color="gray", ls="--", lw=1)
    a.grid(alpha=0.3)
ax[0].set_title("Window reset trace (dashed = window reset)")

for _, r in resets.iterrows():
    ax[0].annotate(f"min {r.OldMinRTTNs/1e3:.0f}→{r.NewMinRTTNs/1e3:.0f}µs",
                   (r.ElapsedNs / 1e6, r.NewMinRTTNs / 1e3), textcoords="offset points", xytext=(5, 10), fontsize=8)

fig.tight_layout()
fig.savefig(out, dpi=150)
print("wrote", out)
