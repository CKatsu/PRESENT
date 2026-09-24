"""
FAKE paho-mqtt (HANYA untuk pengujian; bicara dengan tests/fakes/fake_mqtt_broker.py).
Meniru subset API yang dipakai mqtt_channel.py, termasuk jalur paho 2.x
(CallbackAPIVersion.VERSION2). BUKAN paho asli.
"""
import base64
import json
import socket
import threading

__version__ = "fake-2.0"


class CallbackAPIVersion:
    VERSION1 = 1
    VERSION2 = 2


class _OkReason:
    is_failure = False


class _Msg:
    def __init__(self, topic, payload):
        self.topic, self.payload = topic, payload


class Client:
    def __init__(self, callback_api_version=None, client_id=""):
        self.client_id = client_id
        self.on_connect = self.on_subscribe = self.on_message = None
        self._sock = None
        self._thread = None
        self._wl = threading.Lock()
        self._mid = 0

    def max_inflight_messages_set(self, n): pass
    def max_queued_messages_set(self, n): pass

    def connect(self, host, port, keepalive=60):
        self._sock = socket.create_connection((host, port), timeout=5)
        self._sock.settimeout(None)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._send({"op": "connect"})

    def _send(self, obj):
        with self._wl:
            self._sock.sendall((json.dumps(obj) + "\n").encode())

    def loop_start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        f = self._sock.makefile("rb")
        try:
            for raw in f:
                m = json.loads(raw)
                if m["op"] == "connack" and self.on_connect:
                    self.on_connect(self, None, {}, _OkReason(), None)
                elif m["op"] == "suback" and self.on_subscribe:
                    self._mid += 1
                    self.on_subscribe(self, None, self._mid, [1], None)
                elif m["op"] == "msg" and self.on_message:
                    self.on_message(self, None, _Msg(m["topic"], base64.b64decode(m["payload"])))
        except (OSError, ValueError):
            pass

    def subscribe(self, topic, qos=0):
        self._send({"op": "sub", "topic": topic})

    def publish(self, topic, payload, qos=0):
        self._send({"op": "pub", "topic": topic, "payload": base64.b64encode(payload).decode()})

    def loop_stop(self): pass

    def disconnect(self):
        try:
            self._sock.close()
        except OSError:
            pass
