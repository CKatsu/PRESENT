"""
analyze.py
==========
Mengolah data mentah (results/*.csv, data/log.sqlite) menjadi statistik deskriptif,
tabel, grafik, dan dashboard/summary.json (Tabel 1 kerangka).

Aturan: HANYA menghitung dari data mentah yang ada. Tanpa data -> tabel/dashboard
menampilkan placeholder [HASIL PENGUJIAN]; tidak ada angka rekaan.

Unit statistik (n = 31): NILAI RINGKASAN PER RONDE (1 ronde = 1 pengulangan; pada
konkurensi N, nilai per ronde = rata-rata dari N pesan pada ronde itu).
Rumus (dilaporkan juga di README):
  mean  = (1/n) * sum(x_i)
  SD    = sqrt( sum((x_i - mean)^2) / (n-1) )                  (sampel, ddof=1)
  CI95  = mean +/- t_{0.975, n-1} * SD / sqrt(n)               (distribusi t)
  DR    = paket tampered ditolak / paket tampered yang dijawab
  FRR   = paket normal ditolak  / paket normal yang dijawab
  CI95 untuk proporsi (DR/FRR) = interval Clopper-Pearson (eksak)
  Throughput (agregat, per ronde) = total byte PLAINTEXT ronde / waktu-dinding ronde
  CPU%  (per blok) = sum(delta waktu-CPU proses) / sum(waktu-dinding) * 100  (% satu core)
Persen selisih / speedup antar konfigurasi: (B - A)/A * 100 dan A/B.

Pemilihan sesi: default `--session latest` = sesi terbaru per (skenario, jalur)
agar 31 pengulangan tidak tercampur antar sesi. `--session all` menggabungkan semua.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import sqlite3
import sys
import time

import numpy as np
import pandas as pd
from scipy import stats

import config

BLOCK_KEYS = ["scenario", "transport", "link", "key_bits", "payload_bytes", "concurrency"]


# ---------------------------------------------------------------------------
# Statistik
# ---------------------------------------------------------------------------
def desc(x) -> dict:
    a = np.asarray(pd.Series(x).dropna(), dtype=float)
    n = len(a)
    if n == 0:
        return {"n": 0, "mean": None, "sd": None, "ci_lo": None, "ci_hi": None, "median": None, "min": None, "max": None}
    mean = float(a.mean())
    sd = float(a.std(ddof=1)) if n > 1 else None
    if n > 1:
        half = float(stats.t.ppf(0.975, n - 1) * sd / math.sqrt(n))
        lo, hi = mean - half, mean + half
    else:
        lo = hi = None
    return {"n": n, "mean": mean, "sd": sd, "ci_lo": lo, "ci_hi": hi, "median": float(np.median(a)),
            "min": float(a.min()), "max": float(a.max())}


def clopper_pearson(k: int, n: int, alpha: float = 0.05):
    if n == 0:
        return None, None
    lo = 0.0 if k == 0 else stats.beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else stats.beta.ppf(1 - alpha / 2, k + 1, n - k)
    return float(lo), float(hi)


def _clean(o):
    if isinstance(o, dict):
        return {k: _clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_clean(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating, float)):
        return None if (o is None or math.isnan(o) or math.isinf(o)) else float(o)
    if isinstance(o, (np.bool_,)):
        return bool(o)
    return o


# ---------------------------------------------------------------------------
# Pemuatan data
# ---------------------------------------------------------------------------
def _read(path: str) -> pd.DataFrame:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return pd.DataFrame()
    return pd.read_csv(path)


def _select_sessions(df: pd.DataFrame, mode: str) -> pd.DataFrame:
    if df.empty or mode == "all" or "session_id" not in df.columns:
        return df
    if mode != "latest":
        return df[df.session_id == mode]
    keep = []
    for (_, _), g in df.groupby(["scenario", "transport"]):
        latest = g.loc[g["t_send_unix" if "t_send_unix" in g else "t_start_unix"].idxmax(), "session_id"]
        keep.append(g[g.session_id == latest])
    return pd.concat(keep) if keep else df


def load_perf(session_mode: str):
    msgs, runs = [], []
    for s in ("S1", "S2", "S3"):
        m = _select_sessions(_read(config.metrics_csv_path("device", s)), session_mode)
        r = _select_sessions(_read(config.metrics_csv_path("runs", s)), session_mode)
        if not m.empty:
            msgs.append(m)
        if not r.empty:
            runs.append(r)
    return (pd.concat(msgs, ignore_index=True) if msgs else pd.DataFrame(),
            pd.concat(runs, ignore_index=True) if runs else pd.DataFrame())


# ---------------------------------------------------------------------------
# Performa (S1-S3)
# ---------------------------------------------------------------------------
def build_rounds(msgs: pd.DataFrame, runs: pd.DataFrame) -> pd.DataFrame:
    if msgs.empty:
        return pd.DataFrame()
    rk = BLOCK_KEYS + ["session_id", "round"]
    ok = msgs[~msgs.lost.astype(bool)].copy()
    ok["rtt_ms"] = ok.rtt_s * 1e3
    ok["e2e_ms"] = ok.e2e_s * 1e3
    ok["encrypt_ms"] = ok.encrypt_s * 1e3
    ok["mac_ms"] = ok.mac_s * 1e3
    g = ok.groupby(rk).agg(rtt_ms=("rtt_ms", "mean"), e2e_ms=("e2e_ms", "mean"), encrypt_ms=("encrypt_ms", "mean"),
                           mac_ms=("mac_ms", "mean"), n_ok=("seq", "count"), ciphertext_bytes=("ciphertext_bytes", "mean"),
                           wire_bytes=("wire_bytes", "mean")).reset_index()
    if not runs.empty:
        g = g.merge(runs[rk + ["wall_s", "plain_bytes_total", "tx_cpu_s", "rx_cpu_s", "rx_wall_s", "tx_rss_mb",
                                "rx_rss_mb", "n_lost"]], on=rk, how="left")
        g["throughput_kBps"] = g.plain_bytes_total / g.wall_s / 1e3
        g["tx_cpu_pct"] = g.tx_cpu_s / g.wall_s * 100
        g["rx_cpu_pct"] = g.rx_cpu_s / g.rx_wall_s * 100
    # waktu kripto MURNI hanya valid tanpa kontensi (1 perangkat); pada N>1 memuat waktu tunggu GIL
    g.loc[g.concurrency > 1, ["encrypt_ms", "mac_ms"]] = np.nan
    g["crypto_throughput_kBps"] = g.payload_bytes / ((g.encrypt_ms + g.mac_ms) / 1e3) / 1e3
    return g


def summarize_blocks(rounds: pd.DataFrame, msgs: pd.DataFrame) -> pd.DataFrame:
    rows = []
    metric_cols = ["rtt_ms", "e2e_ms", "throughput_kBps", "encrypt_ms", "mac_ms", "crypto_throughput_kBps",
                   "tx_cpu_pct", "rx_cpu_pct", "tx_rss_mb", "rx_rss_mb"]
    for key, g in rounds.groupby(BLOCK_KEYS):
        row = dict(zip(BLOCK_KEYS, key))
        row["n_rounds"] = len(g)
        for m in metric_cols:
            if m in g:
                d = desc(g[m])
                for k, v in d.items():
                    row[f"{m}_{k}"] = v
        # CPU per blok (lebih tahan terhadap resolusi jam CPU yang kasar)
        if "tx_cpu_s" in g:
            row["tx_cpu_pct_block"] = g.tx_cpu_s.sum() / g.wall_s.sum() * 100
            v = g.dropna(subset=["rx_cpu_s", "rx_wall_s"])
            row["rx_cpu_pct_block"] = (v.rx_cpu_s.sum() / v.rx_wall_s.sum() * 100) if len(v) else np.nan
            row["n_lost_total"] = int(g.n_lost.sum())
        mm = msgs[(msgs[BLOCK_KEYS] == pd.Series(key, index=BLOCK_KEYS)).all(axis=1) & ~msgs.lost.astype(bool)]
        if len(mm):
            r = mm.rtt_s * 1e3
            row["rtt_msg_p95_ms"], row["rtt_msg_max_ms"] = float(r.quantile(0.95)), float(r.max())
            row["ciphertext_bytes"] = float(mm.ciphertext_bytes.mean())
            row["wire_bytes"] = float(mm.wire_bytes.mean())
            row["overhead_pct"] = float((mm.ciphertext_bytes.mean() - key[4]) / key[4] * 100)
            row["n_messages"] = len(mm)
            row["all_accepted"] = bool(mm.accepted.astype(bool).all())
        rows.append(row)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Keamanan (S4)
# ---------------------------------------------------------------------------
def analyze_s4(session_mode: str):
    d = _select_sessions(_read(config.metrics_csv_path("device", "S4")), session_mode)
    if d.empty:
        return pd.DataFrame(), []
    d = d.copy()
    d["tamper_variant"] = d.tamper_variant.fillna("")
    d["lost"] = d.lost.astype(bool)
    d["accepted"] = d.accepted.astype("boolean").fillna(False).astype(bool)
    rows = []
    for (tr, link, kb), g in d.groupby(["transport", "link", "key_bits"]):
        def add(label, sub, cond):
            answered = sub[~sub.lost]
            n = len(answered)
            k_rej = int((~answered.accepted).sum())
            lo, hi = clopper_pearson(k_rej, n)
            rows.append({"transport": tr, "link": link, "key_bits": int(kb), "kondisi": cond, "varian": label,
                         "dikirim": len(sub), "lost": int(sub.lost.sum()), "dijawab": n, "ditolak": k_rej,
                         "diterima": n - k_rej,
                         "rate": (k_rej / n) if n else None,      # DR untuk tampered, FRR untuk normal
                         "ci_lo": lo, "ci_hi": hi,
                         "metrik": "detection_rate" if cond == "tampered" else "false_rejection_rate"})
        add("(semua normal)", g[g.condition == "normal"], "normal")
        tam = g[g.condition == "tampered"]
        for v, gv in tam.groupby("tamper_variant"):
            add(v, gv, "tampered")
        add("(semua tampered)", tam, "tampered")
    notes = []
    srv = _read(config.metrics_csv_path("server", "all"))
    if not srv.empty:
        sd = srv[srv.scenario == "S4"]
        n_dev = len(d)
        n_srv = len(sd)
        notes.append(f"Cross-check: baris S4 sisi device={n_dev}, sisi server={n_srv} "
                     + ("(cocok)" if n_dev == n_srv else "(BERBEDA -- berkas server mungkin memuat beberapa sesi/pesan lost)"))
    return pd.DataFrame(rows), notes


# ---------------------------------------------------------------------------
# Sensor (streaming) dari SQLite
# ---------------------------------------------------------------------------
def load_sensor(limit: int = 200) -> dict:
    if not os.path.exists(config.DB_PATH):
        return {"available": False}
    try:
        conn = sqlite3.connect(config.DB_PATH)
        df = pd.read_sql_query(
            "SELECT device_id, seq, scenario, transport, link, key_bits, received_at_unix, temp_c, hum_pct, pres_hpa, "
            "is_synthetic_sensor FROM valid_readings WHERE scenario='STREAM' ORDER BY received_at_unix DESC LIMIT ?",
            conn, params=(limit,))
        total = conn.execute("SELECT COUNT(*), SUM(is_synthetic_sensor) FROM valid_readings").fetchone()
        conn.close()
    except sqlite3.Error:
        return {"available": False}
    if df.empty:
        return {"available": True, "stream_rows": 0, "db_total_valid": total[0], "db_total_synthetic": total[1] or 0}
    df = df.sort_values("received_at_unix")
    return {"available": True, "stream_rows": len(df), "db_total_valid": total[0], "db_total_synthetic": total[1] or 0,
            "temp": desc(df.temp_c), "hum": desc(df.hum_pct), "pres": desc(df.pres_hpa),
            "synthetic_fraction": float(df.is_synthetic_sensor.mean()),
            "rows": df.to_dict("records")}


# ---------------------------------------------------------------------------
# Grafik (matplotlib) -- error bar = CI 95%; palet biru/oranye (slot 1-2 palet validasi)
# ---------------------------------------------------------------------------
C_BLUE, C_ORANGE = "#2a78d6", "#eb6834"


def _style(ax, xlabel, ylabel, title):
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=10)
    ax.grid(axis="y", alpha=0.25)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)


def make_charts(summary: pd.DataFrame, s4: pd.DataFrame) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    out = []
    colors = {"uart": C_BLUE, "mqtt": C_ORANGE}

    def save(fig, name):
        p = os.path.join(config.CHARTS_DIR, name)
        fig.tight_layout()
        fig.savefig(p, dpi=150)
        plt.close(fig)
        out.append(p)

    def errline(ax, x, g, col, color, label, **kw):
        y = g[f"{col}_mean"].to_numpy(float)
        err = (g[f"{col}_ci_hi"] - g[f"{col}_mean"]).to_numpy(float)
        ax.errorbar(x, y, yerr=np.nan_to_num(err), marker="o", ms=5, lw=2, capsize=3, color=color, label=label, **kw)

    if not summary.empty:
        s2 = summary[summary.scenario == "S2"].sort_values("payload_bytes")
        if not s2.empty:
            for col, ylab, name, ttl in (("rtt_ms", "RTT (ms)", "s2_rtt_vs_payload.png", "S2: RTT vs ukuran payload (mean, CI 95%, n=31 ronde)"),
                                         ("throughput_kBps", "Throughput (kB/s, plaintext)", "s2_throughput_vs_payload.png",
                                          "S2: throughput vs ukuran payload (mean, CI 95%)")):
                fig, ax = plt.subplots(figsize=(6, 3.8))
                for tr, g in s2.groupby("transport"):
                    errline(ax, g.payload_bytes, g, col, colors.get(tr, "gray"), f"{tr.upper()} ({g.link.iloc[0]})")
                ax.set_xscale("log", base=2)
                ax.set_xticks(sorted(s2.payload_bytes.unique()))
                ax.set_xticklabels([str(v) for v in sorted(s2.payload_bytes.unique())])
                ax.set_ylim(bottom=0)
                _style(ax, "Ukuran payload plaintext (byte)", ylab, ttl)
                ax.legend(frameon=False)
                save(fig, name)
            if s2.encrypt_ms_mean.notna().any():
                fig, ax = plt.subplots(figsize=(6, 3.8))
                for tr, g in s2.groupby("transport"):
                    ls = "-" if tr == "uart" else "--"
                    errline(ax, g.payload_bytes, g, "encrypt_ms", C_BLUE, f"CBC-encrypt [{tr.upper()}]", ls=ls)
                    errline(ax, g.payload_bytes, g, "mac_ms", C_ORANGE, f"CBC-MAC [{tr.upper()}]", ls=ls)
                ax.set_xscale("log", base=2)
                ax.set_xticks(sorted(s2.payload_bytes.unique()))
                ax.set_xticklabels([str(v) for v in sorted(s2.payload_bytes.unique())])
                ax.set_ylim(bottom=0)
                _style(ax, "Ukuran payload plaintext (byte)", "Waktu kripto murni di HOST Python (ms)",
                       "S2: waktu enkripsi & MAC (1 perangkat; bukan waktu ESP32)")
                ax.legend(frameon=False, fontsize=8)
                save(fig, "s2_crypto_time_vs_payload.png")

        s3 = summary[summary.scenario == "S3"]
        if not s3.empty:
            for col, ylab, name, ttl in (("rtt_ms", "RTT (ms)", "s3_rtt_vs_concurrency.png", "S3: RTT"),
                                         ("throughput_kBps", "Throughput agregat (kB/s)", "s3_throughput_vs_concurrency.png", "S3: throughput"),
                                         ("rx_cpu_pct_block", "CPU receiver (% satu core, per blok)", "s3_cpu_vs_concurrency.png", "S3: CPU receiver"),
                                         ("rx_rss_mb_mean", "RAM receiver (RSS, MB)", "s3_ram_vs_concurrency.png", "S3: RAM receiver")):
                trs = sorted(s3.transport.unique())
                fig, axes = plt.subplots(1, len(trs), figsize=(5.2 * len(trs), 3.8), squeeze=False, sharey=True)
                for ax, tr in zip(axes[0], trs):
                    for kb, col_c in ((80, C_BLUE), (128, C_ORANGE)):
                        g = s3[(s3.transport == tr) & (s3.key_bits == kb)].sort_values("concurrency")
                        if g.empty:
                            continue
                        if f"{col}_ci_hi" in g:
                            errline(ax, g.concurrency, g, col, col_c, f"PRESENT-{kb}")
                        else:
                            ax.plot(g.concurrency, g[col], marker="o", lw=2, color=col_c, label=f"PRESENT-{kb}")
                    ax.set_xscale("log")
                    ax.set_xticks(sorted(s3.concurrency.unique()))
                    ax.set_xticklabels([str(v) for v in sorted(s3.concurrency.unique())])
                    ax.set_ylim(bottom=0)
                    _style(ax, "Jumlah perangkat konkuren", ylab, f"{ttl} -- {tr.upper()}")
                    ax.legend(frameon=False)
                save(fig, name)

    if not s4.empty:
        t = s4[(s4.kondisi == "tampered") & (~s4.varian.str.startswith("("))]
        if not t.empty:
            fig, ax = plt.subplots(figsize=(7.5, 4.3))
            variants = list(config.S4_TAMPER_VARIANTS)
            combos = sorted(set(zip(t.transport, t.key_bits)))
            w = 0.8 / max(1, len(combos))
            palette = [C_BLUE, C_ORANGE, "#1baf7a", "#eda100"]
            for i, (tr, kb) in enumerate(combos):
                vals = []
                for v in variants:
                    r = t[(t.transport == tr) & (t.key_bits == kb) & (t.varian == v)]
                    vals.append(100 * r.rate.iloc[0] if len(r) and r.rate.iloc[0] is not None else np.nan)
                ax.bar(np.arange(len(variants)) + i * w, vals, w * 0.9, color=palette[i % 4], label=f"{tr.upper()} / {kb}-bit")
            ax.set_xticks(np.arange(len(variants)) + w * (len(combos) - 1) / 2)
            ax.set_xticklabels(variants, fontsize=8)
            ax.set_ylim(0, 105)
            _style(ax, "Varian manipulasi", "Detection rate (%)", "S4: detection rate per varian tampered")
            ax.legend(frameon=False, fontsize=8, ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.2))
            save(fig, "s4_detection_rate.png")
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
CAVEATS = [
    "CPU/RAM diukur pada proses sender & receiver di komputer HOST (psutil/process_time), bukan pada mikrokontroler.",
    "Latensi = kripto + pemrosesan jalur (UART/MQTT) + pemrosesan receiver; bukan latensi jaringan nirkabel skala luas.",
    "Data sensor SINTETIS (BME280 belum terpasang) -- ditandai di setiap rekaman; bukan hasil pembacaan fisik.",
    "Konkurensi = thread dalam satu proses Python (GIL), bukan perangkat fisik paralel; waktu kripto murni hanya valid pada 1 perangkat.",
    "Jalur 'UART' dengan link=tcp-loopback adalah simulasi loopback lokal, bukan pengukuran UART hardware.",
    "Keamanan diuji pada integritas/autentikasi (CBC-MAC), bukan kriptanalisis PRESENT; tag hanya 64 bit (blok PRESENT).",
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--session", default="latest", help="latest | all | <session_id>")
    ap.add_argument("--no-charts", action="store_true")
    args = ap.parse_args(argv)

    msgs, runs = load_perf(args.session)
    rounds = build_rounds(msgs, runs)
    summary = summarize_blocks(rounds, msgs) if not rounds.empty else pd.DataFrame()
    s4, notes = analyze_s4(args.session)
    sensor = load_sensor()

    if not rounds.empty:
        rounds.to_csv(os.path.join(config.RESULTS_DIR, "rounds_aggregated.csv"), index=False)
    if not summary.empty:
        summary.to_csv(os.path.join(config.RESULTS_DIR, "summary_stats.csv"), index=False)
    if not s4.empty:
        s4.to_csv(os.path.join(config.RESULTS_DIR, "s4_detection.csv"), index=False)
    charts = [] if args.no_charts else make_charts(summary, s4)

    meta_path = os.path.join(config.RESULTS_DIR, "run_metadata.json")
    try:
        meta = json.load(open(meta_path))
    except (OSError, ValueError):
        meta = []
    has_data = not summary.empty or not s4.empty
    out = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "ok" if has_data else "belum_ada_data",
        "placeholder": None if has_data else "[HASIL PENGUJIAN] Belum ada data. Jalankan receiver_server.py + device_sim.py lalu analyze.py.",
        "session_mode": args.session,
        "blocks": summary.to_dict("records") if not summary.empty else [],
        "s4": s4.to_dict("records") if not s4.empty else [],
        "notes": notes, "caveats": CAVEATS, "sessions": meta[-4:], "sensor": sensor,
        "charts": [os.path.relpath(c, config.BASE_DIR) for c in charts],
    }
    with open(config.SUMMARY_JSON_PATH, "w") as f:
        json.dump(_clean(out), f, indent=1)
    print(f"analyze.py selesai: status={out['status']}  blok={len(summary)}  baris-S4={len(s4)}  grafik={len(charts)}")
    print(f"  -> {config.SUMMARY_JSON_PATH}")
    if not summary.empty:
        show = summary[BLOCK_KEYS + ["n_rounds", "rtt_ms_mean", "rtt_ms_sd", "rtt_ms_ci_lo", "rtt_ms_ci_hi", "throughput_kBps_mean"]]
        print(show.round(3).to_string(index=False))
    for n in notes:
        print("  *", n)


if __name__ == "__main__":
    main()
