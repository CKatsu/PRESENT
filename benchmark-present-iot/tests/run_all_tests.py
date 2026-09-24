"""
tests/run_all_tests.py -- menjalankan semua uji otomatis berurutan (berhenti bila ada yang gagal).
KAT & cross-check C WAJIB lulus sebelum pengambilan data. Mode 'real' (pyserial/paho/Mosquitto
asli) tidak dijalankan di sini -- lihat tests/test_e2e_smoke.py real.
"""
import os
import subprocess
import sys

T = os.path.dirname(os.path.abspath(__file__))
STEPS = [
    ("KAT PRESENT + CBC + CBC-MAC + tamper", ["test_present_kat.py"]),
    ("Cross-check C firmware vs Python", ["crosscheck_c.py"]),
    ("Payload firmware -> receiver (host, stub Arduino)", ["test_firmware_host.py"]),
    ("verify_capture (pcap/pcapng/raw)", ["test_verify_capture.py"]),
    ("End-to-end TCP (jalur nyata stdlib)", ["test_e2e_smoke.py", "tcp"]),
    ("End-to-end UART+MQTT dengan pyserial/paho PALSU", ["test_e2e_smoke.py", "fakes"]),
]
for name, cmd in STEPS:
    if "PALSU" in name and os.name == "nt":
        print(f"\n===== {name} =====\nDILEWATI di Windows (fake pyserial butuh fcntl, hanya Linux/macOS)")
        continue
    print(f"\n===== {name} =====", flush=True)
    r = subprocess.run([sys.executable, os.path.join(T, cmd[0])] + cmd[1:])
    if r.returncode != 0:
        sys.exit(f"GAGAL: {name}")
print("\nSEMUA UJI OTOMATIS LULUS")
