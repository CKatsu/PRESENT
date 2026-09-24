"""
FAKE broker MQTT (HANYA untuk pengujian logika mqtt_channel.py di lingkungan tanpa
Mosquitto/paho). Protokol-nya BUKAN MQTT sungguhan: JSON per baris via TCP
({"op":"sub"|"pub", "topic":..., "payload":<base64>}) dan hanya dipahami
tests/fakes/paho (paho palsu). Mosquitto + paho-mqtt asli harus diuji di komputer Anda
(lihat tests/smoke_mqtt.py).

Jalankan: python3 tests/fakes/fake_mqtt_broker.py 18830
"""
import json
import socket
import sys
import threading

subs = []            # (conn, filter)
lock = threading.Lock()


def topic_match(flt: str, topic: str) -> bool:
    f, t = flt.split("/"), topic.split("/")
    for i, part in enumerate(f):
        if part == "#":
            return True
        if i >= len(t) or (part != "+" and part != t[i]):
            return False
    return len(f) == len(t)


def serve(conn: socket.socket):
    f = conn.makefile("rb")
    wl = threading.Lock()

    def send(obj):
        with wl:
            conn.sendall((json.dumps(obj) + "\n").encode())

    try:
        for raw in f:
            msg = json.loads(raw)
            if msg["op"] == "connect":
                send({"op": "connack"})
            elif msg["op"] == "sub":
                with lock:
                    subs.append((conn, msg["topic"], send))
                send({"op": "suback"})
            elif msg["op"] == "pub":
                with lock:
                    targets = [s for c, flt, s in subs if topic_match(flt, msg["topic"])]
                for s in targets:
                    try:
                        s({"op": "msg", "topic": msg["topic"], "payload": msg["payload"]})
                    except OSError:
                        pass
    except (OSError, ValueError):
        pass
    finally:
        with lock:
            subs[:] = [x for x in subs if x[0] is not conn]
        conn.close()


def main(port: int):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(128)
    print(f"fake broker on 127.0.0.1:{port}", flush=True)
    while True:
        c, _ = srv.accept()
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=serve, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main(int(sys.argv[1]))
