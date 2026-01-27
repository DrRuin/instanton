"""Congestion."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Any


class CongestionState(Enum):
    STARTUP = "startup"
    DRAIN = "drain"
    PROBE_BW = "probe_bw"
    PROBE_RTT = "probe_rtt"


@dataclass
class RttSample:
    rtt_ms: float
    timestamp: float


@dataclass
class BandwidthSample:
    bytes_delivered: int
    interval_ms: float
    timestamp: float

    @property
    def bandwidth_bps(self) -> float:
        if self.interval_ms <= 0:
            return 0.0
        return (self.bytes_delivered * 8 * 1000) / self.interval_ms


class CongestionController:
    def __init__(
        self,
        initial_cwnd: int = 32 * 1024,
        min_cwnd: int = 4 * 1024,
        max_cwnd: int = 16 * 1024 * 1024,
        pacing_gain: float = 1.25,
        drain_gain: float = 0.75,
        probe_rtt_duration_ms: float = 200.0,
    ) -> None:
        self._initial_cwnd = initial_cwnd
        self._min_cwnd = min_cwnd
        self._max_cwnd = max_cwnd
        self._pacing_gain = pacing_gain
        self._drain_gain = drain_gain
        self._probe_rtt_duration_ms = probe_rtt_duration_ms

        self._cwnd = initial_cwnd
        self._state = CongestionState.STARTUP
        self._rtt_samples: deque[RttSample] = deque(maxlen=100)
        self._bw_samples: deque[BandwidthSample] = deque(maxlen=100)
        self._bytes_in_flight = 0
        self._bytes_delivered = 0
        self._last_send_time = time.monotonic()
        self._state_start_time = time.monotonic()
        self._min_rtt_ms = float("inf")
        self._max_bw_bps = 0.0
        self._filled_pipe = False
        self._probe_rtt_min_cwnd_target = 0
        self._pacing_rate_bps = 0.0
        self._loss_count = 0
        self._startup_full_bw_count = 0
        self._startup_full_bw = 0.0

    @property
    def cwnd(self) -> int:
        return self._cwnd

    @property
    def state(self) -> CongestionState:
        return self._state

    @property
    def pacing_rate(self) -> float:
        return self._pacing_rate_bps

    @property
    def can_send(self) -> bool:
        return self._bytes_in_flight < self._cwnd

    @property
    def available_cwnd(self) -> int:
        return max(0, self._cwnd - self._bytes_in_flight)

    def on_packet_sent(self, size: int) -> None:
        self._bytes_in_flight += size
        self._last_send_time = time.monotonic()

    def on_packet_acked(self, size: int, rtt_ms: float) -> None:
        self._bytes_in_flight = max(0, self._bytes_in_flight - size)
        self._bytes_delivered += size

        self._rtt_samples.append(RttSample(rtt_ms=rtt_ms, timestamp=time.monotonic()))
        if rtt_ms < self._min_rtt_ms:
            self._min_rtt_ms = rtt_ms

        now = time.monotonic()
        interval_ms = (now - self._last_send_time) * 1000
        if interval_ms > 0:
            sample = BandwidthSample(
                bytes_delivered=size,
                interval_ms=max(interval_ms, 1.0),
                timestamp=now,
            )
            self._bw_samples.append(sample)
            if sample.bandwidth_bps > self._max_bw_bps:
                self._max_bw_bps = sample.bandwidth_bps

        self._update_state()
        self._update_cwnd()
        self._update_pacing_rate()

    def on_packet_lost(self, size: int) -> None:
        self._bytes_in_flight = max(0, self._bytes_in_flight - size)
        self._loss_count += 1

        if self._state == CongestionState.STARTUP:
            self._enter_drain()
        elif self._state == CongestionState.PROBE_BW:
            self._cwnd = max(self._min_cwnd, int(self._cwnd * 0.9))

    def _update_state(self) -> None:
        now = time.monotonic()
        state_duration = now - self._state_start_time

        if self._state == CongestionState.STARTUP:
            if self._filled_pipe or self._check_full_pipe():
                self._enter_drain()

        elif self._state == CongestionState.DRAIN:
            if self._bytes_in_flight <= self._get_bdp():
                self._enter_probe_bw()

        elif self._state == CongestionState.PROBE_BW:
            if now - self._get_last_probe_rtt_time() > 10.0:
                self._enter_probe_rtt()

        elif self._state == CongestionState.PROBE_RTT:
            if state_duration * 1000 >= self._probe_rtt_duration_ms:
                if self._filled_pipe:
                    self._enter_probe_bw()
                else:
                    self._enter_startup()

    def _check_full_pipe(self) -> bool:
        if len(self._bw_samples) < 3:
            return False

        current_bw = self._get_current_bw()
        if current_bw > self._startup_full_bw * 1.25:
            self._startup_full_bw = current_bw
            self._startup_full_bw_count = 0
            return False

        self._startup_full_bw_count += 1
        if self._startup_full_bw_count >= 3:
            self._filled_pipe = True
            return True
        return False

    def _get_current_bw(self) -> float:
        if not self._bw_samples:
            return 0.0
        recent = list(self._bw_samples)[-10:]
        return max(s.bandwidth_bps for s in recent) if recent else 0.0

    def _get_bdp(self) -> int:
        if self._min_rtt_ms == float("inf") or self._max_bw_bps == 0:
            return self._initial_cwnd
        bdp_bits = self._max_bw_bps * (self._min_rtt_ms / 1000)
        return max(self._min_cwnd, int(bdp_bits / 8))

    def _get_last_probe_rtt_time(self) -> float:
        return self._state_start_time if self._state == CongestionState.PROBE_RTT else 0.0

    def _enter_startup(self) -> None:
        self._state = CongestionState.STARTUP
        self._state_start_time = time.monotonic()

    def _enter_drain(self) -> None:
        self._state = CongestionState.DRAIN
        self._state_start_time = time.monotonic()

    def _enter_probe_bw(self) -> None:
        self._state = CongestionState.PROBE_BW
        self._state_start_time = time.monotonic()

    def _enter_probe_rtt(self) -> None:
        self._state = CongestionState.PROBE_RTT
        self._state_start_time = time.monotonic()
        self._probe_rtt_min_cwnd_target = max(self._min_cwnd, int(self._cwnd * 0.5))

    def _update_cwnd(self) -> None:
        bdp = self._get_bdp()

        if self._state == CongestionState.STARTUP:
            self._cwnd = min(self._max_cwnd, int(self._cwnd * 2))

        elif self._state == CongestionState.DRAIN:
            target = bdp
            self._cwnd = max(self._min_cwnd, min(self._cwnd, target))

        elif self._state == CongestionState.PROBE_BW:
            self._cwnd = max(self._min_cwnd, int(bdp * self._pacing_gain))

        elif self._state == CongestionState.PROBE_RTT:
            self._cwnd = max(self._min_cwnd, self._probe_rtt_min_cwnd_target)

        self._cwnd = max(self._min_cwnd, min(self._max_cwnd, self._cwnd))

    def _update_pacing_rate(self) -> None:
        if self._min_rtt_ms == float("inf") or self._min_rtt_ms == 0:
            self._pacing_rate_bps = self._max_bw_bps * self._pacing_gain
            return

        if self._state == CongestionState.STARTUP:
            gain = 2.77
        elif self._state == CongestionState.DRAIN:
            gain = self._drain_gain
        elif self._state == CongestionState.PROBE_RTT:
            gain = 1.0
        else:
            gain = self._pacing_gain

        self._pacing_rate_bps = self._max_bw_bps * gain

    def reset(self) -> None:
        self._cwnd = self._initial_cwnd
        self._state = CongestionState.STARTUP
        self._rtt_samples.clear()
        self._bw_samples.clear()
        self._bytes_in_flight = 0
        self._bytes_delivered = 0
        self._min_rtt_ms = float("inf")
        self._max_bw_bps = 0.0
        self._filled_pipe = False
        self._loss_count = 0
        self._startup_full_bw_count = 0
        self._startup_full_bw = 0.0
        self._state_start_time = time.monotonic()

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._state.value,
            "cwnd": self._cwnd,
            "bytes_in_flight": self._bytes_in_flight,
            "min_rtt_ms": self._min_rtt_ms if self._min_rtt_ms != float("inf") else None,
            "max_bw_mbps": round(self._max_bw_bps / 1_000_000, 2) if self._max_bw_bps > 0 else 0,
            "pacing_rate_mbps": round(self._pacing_rate_bps / 1_000_000, 2)
            if self._pacing_rate_bps > 0
            else 0,
            "loss_count": self._loss_count,
            "filled_pipe": self._filled_pipe,
        }
