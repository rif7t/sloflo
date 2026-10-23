#!/usr/bin/env python3
"""Closed-loop load generator with named concurrency profiles.

Every request opens a fresh TCP connection (so each one sends a SYN the XDP
limiter can shed). Writes, next to --out:
  <out>.phases.csv    wall-clock start/end (ns) and target concurrency per phase
  <out>.requests.csv  one row per request: start_ns, end_ns, outcome
"""
import argparse
import asyncio
import csv
import resource
import time

# (target concurrency, seconds)
PROFILES = {
    # control: steady low load; the limiter should stay out of the way
    "neutral": [(20, 55)],
    # low -> increase, held flat -> bigger increase -> drop
    "step": [(20, 10), (200, 15), (800, 15), (20, 15)],
}

REQ = b"GET / HTTP/1.1\r\nHost: sloflo\r\nConnection: close\r\n\r\n"


async def one_request(host, port, timeout, rows):
    start = time.time_ns()
    outcome = "ok"
    try:
        async def go():
            r, w = await asyncio.open_connection(host, port)
            w.write(REQ)
            await w.drain()
            data = await r.read()
            w.close()
            return data
        data = await asyncio.wait_for(go(), timeout)
        if not data.startswith(b"HTTP/1.") or b" 200 " not in data[:20]:
            outcome = "bad"
    except asyncio.TimeoutError:
        outcome = "timeout"
    except OSError:
        outcome = "error"
    rows.append((start, time.time_ns(), outcome))


async def worker(idx, state, host, port, timeout, rows):
    while not state["done"]:
        if idx >= state["target"]:
            await asyncio.sleep(0.05)
            continue
        await one_request(host, port, timeout, rows)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=PROFILES, default="step")
    ap.add_argument("--host", default="10.200.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--scale", type=float, default=1.0, help="multiply phase durations")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
    phases = [(c, d * a.scale) for c, d in PROFILES[a.profile]]
    state = {"target": 0, "done": False}
    rows, phase_rows = [], []
    workers = [asyncio.create_task(worker(i, state, a.host, a.port, a.timeout, rows))
               for i in range(max(c for c, _ in phases))]

    for i, (conc, dur) in enumerate(phases):
        start = time.time_ns()
        state["target"] = conc
        print(f"phase {i}: concurrency={conc} for {dur:.0f}s", flush=True)
        await asyncio.sleep(dur)
        phase_rows.append((i, conc, start, time.time_ns()))

    state["done"] = True
    await asyncio.gather(*workers)

    with open(a.out + ".phases.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Phase", "Concurrency", "StartNs", "EndNs"])
        w.writerows(phase_rows)
    with open(a.out + ".requests.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["StartNs", "EndNs", "Outcome"])
        w.writerows(rows)
    ok = sum(1 for r in rows if r[2] == "ok")
    print(f"{len(rows)} requests, {ok} ok, {len(rows) - ok} failed")


asyncio.run(main())
