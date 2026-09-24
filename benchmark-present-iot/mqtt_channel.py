"""
mqtt_channel.py
================
Jalur publish/subscribe ke broker MQTT (Mosquitto) memakai paho-mqtt
(Tabel 1 & 2 kerangka). AKTIF, bukan stub.

Topik:
  device -> receiver : present/<device_id>/data   (payload = JSON paket terenkripsi)
  receiver -> device : present/<device_id>/ack    (payload = JSON ACK)
Receiver subscribe "present/+/data". Setiap "perangkat" (device_sim) memakai
klien MQTT-nya SENDIRI (50 perangkat = 50 koneksi ke broker), lalu subscribe
topik ACK miliknya.

Kompatibel paho-mqtt 1.x dan 2.x (perbedaan CallbackAPIVersion ditangani).
QoS default 1 (config.MQTT_QOS). Catatan: RTT diukur pada level aplikasi
(publish -> ACK aplikasi), jadi mencakup broker + 2 hop + pemrosesan receiver.

Broker (Mosquitto) di komputer Anda -- lihat README bagian "Setup Mosquitto".
"""

from __future__ import annotations

import json
import queue
import threading
import uuid
from typing import Optional

import channel_base as cb
import config


def _new_client(client_id: str):
    import paho.mqtt.client as mqtt
    try:                                    # paho-mqtt >= 2.0
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    except AttributeError:                  # paho-mqtt 1.x
        return mqtt.Client(client_id=client_id)


def _rc_failed(rc) -> bool:
    """v1: int (0=ok). v2: ReasonCode (.is_failure)."""
    failed = getattr(rc, "is_failure", None)
    return bool(failed) if failed is not None else rc != 0


class MqttChannel(cb.Channel):
    name = "mqtt"
    link = "mqtt-broker"

    def __init__(self, role: str, device_id: Optional[str] = None,
                 host: str = config.MQTT_HOST, port: int = config.MQTT_PORT,
                 qos: int = config.MQTT_QOS, wire_tap=None):
        super().__init__(wire_tap)
        if role not in ("device", "receiver"):
            raise ValueError("role harus 'device' atau 'receiver'")
        if role == "device" and not device_id:
            raise ValueError("role device butuh device_id")
        self.role, self.device_id = role, device_id
        self.host, self.port, self.qos = host, port, qos
        self._client = None
        self._connected = threading.Event()
        self._subscribed = threading.Event()
        self._conn_failed: Optional[str] = None
        self._inbox: "queue.Queue[dict]" = queue.Queue()

    # --- callback paho (signature fleksibel v1/v2) --------------------------
    def _on_connect(self, client, userdata, flags, rc, *extra):
        if _rc_failed(rc):
            self._conn_failed = str(rc)
        else:
            topic = config.MQTT_TOPIC_ACK.format(device_id=self.device_id) if self.role == "device" \
                else config.MQTT_SUB_ALL_DATA
            client.subscribe(topic, qos=self.qos)
        self._connected.set()

    def _on_subscribe(self, client, userdata, mid, *extra):
        self._subscribed.set()

    def _on_message(self, client, userdata, msg):
        try:
            obj = json.loads(msg.payload.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return
        if not isinstance(obj, dict):
            return
        if self.role == "device":
            if self._ack_cb is not None:
                self._ack_cb(obj)
        else:
            self._inbox.put(obj)

    # --- Channel ------------------------------------------------------------
    def connect(self) -> None:
        cid = f"present-{self.role}-{self.device_id or 'rx'}-{uuid.uuid4().hex[:6]}"
        c = _new_client(cid)
        c.on_connect, c.on_subscribe, c.on_message = self._on_connect, self._on_subscribe, self._on_message
        try:
            c.max_inflight_messages_set(1000)
            c.max_queued_messages_set(0)
        except Exception:                                   # noqa: BLE001 (API berbeda antar versi)
            pass
        self._client = c
        try:
            c.connect(self.host, self.port, keepalive=config.MQTT_KEEPALIVE_S)
        except OSError as exc:
            raise ConnectionError(
                f"Tidak bisa terhubung ke broker MQTT {self.host}:{self.port} ({exc}). "
                "Pastikan Mosquitto berjalan (lihat README 'Setup Mosquitto').") from exc
        c.loop_start()
        if not self._connected.wait(10.0) or self._conn_failed:
            raise ConnectionError(f"Koneksi MQTT gagal: {self._conn_failed or 'timeout'}")
        if not self._subscribed.wait(10.0):
            raise ConnectionError("Subscribe MQTT tidak dikonfirmasi broker (timeout)")

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:                               # noqa: BLE001
                pass
            self._client = None

    def send_data(self, env: dict) -> int:
        payload = json.dumps(env, separators=(",", ":")).encode("utf-8")
        if self.wire_tap is not None:
            self.wire_tap.write(payload)
        self._client.publish(config.MQTT_TOPIC_DATA.format(device_id=self.device_id), payload, qos=self.qos)
        return len(payload)

    def recv_data(self, timeout_s: float) -> Optional[dict]:
        try:
            return self._inbox.get(timeout=timeout_s)
        except queue.Empty:
            return None

    def send_ack(self, ack: dict) -> None:
        topic = config.MQTT_TOPIC_ACK.format(device_id=ack.get("device_id", "unknown"))
        self._client.publish(topic, json.dumps(ack, separators=(",", ":")).encode("utf-8"), qos=self.qos)
