#!/usr/bin/env python3
"""合成宣传片配乐（纯标准库，不依赖任何音频素材）。

调式 A 小调，84 BPM，pad + 低音 + 琶音 + 轻打击，段落切换点加 whoosh。
场景切换处用 --marks 传入时间点（秒），让转场和音乐对上。

    python promo/make_bgm.py --duration 36.6 --out promo/bgm.wav
"""

from __future__ import annotations

import argparse
import math
import os
import random
import struct
import wave

SR = 44100
BPM = 84.0
BEAT = 60.0 / BPM
BAR = BEAT * 4

# A 小调：Am - F - C - G
CHORDS = [
    (110.00, 130.81, 164.81),   # Am
    (87.31, 110.00, 130.81),    # F
    (130.81, 164.81, 196.00),   # C
    (98.00, 123.47, 146.83),    # G
]


def lowpass(buf: list, cutoff: float) -> list:
    a = 1.0 - math.exp(-2.0 * math.pi * cutoff / SR)
    out = [0.0] * len(buf)
    y = 0.0
    for i, x in enumerate(buf):
        y += a * (x - y)
        out[i] = y
    return out


def highpass(buf: list, cutoff: float) -> list:
    lp = lowpass(buf, cutoff)
    return [buf[i] - lp[i] for i in range(len(buf))]


def reverb(buf: list, mix: float = 0.26) -> list:
    """Schroeder：3 梳状 + 2 全通，给声音一点空间感。"""
    combs = [(int(SR * d), fb) for d, fb in
             ((0.0297, 0.78), (0.0371, 0.76), (0.0411, 0.74))]
    out = [0.0] * len(buf)
    for delay, fb in combs:
        line = [0.0] * delay
        idx = 0
        for i in range(len(buf)):
            y = line[idx]
            line[idx] = buf[i] + y * fb      # 标准梳状滤波：反馈系数 < 1 才稳定
            out[i] += y
            idx += 1
            if idx == delay:
                idx = 0
    for delay, g in ((int(SR * 0.0050), 0.7), (int(SR * 0.0017), 0.7)):
        line = [0.0] * delay
        idx = 0
        for i in range(len(buf)):
            y = line[idx]
            x = out[i]
            line[idx] = x + y * g
            out[i] = y - g * x
            idx += 1
            if idx == delay:
                idx = 0
    scale = mix / len(combs)
    return [out[i] * scale for i in range(len(out))]


def note(buf: list, start: float, dur: float, freq: float, amp: float,
         attack: float, decay: float, harmonics=(1.0,), detune: float = 0.0) -> None:
    """往缓冲里加一个带包络的音。harmonics 决定音色（正弦/三角等）。"""
    n0 = int(start * SR)
    total = int(dur * SR)
    if total <= 0:
        return
    if n0 >= len(buf):
        return
    total = min(total, len(buf) - n0)
    atk = max(1, int(attack * SR))
    env = 0.0
    two_pi = 2.0 * math.pi
    for i in range(total):
        t = i / SR
        if i < atk:
            env = env + (amp / atk) if env < amp else env
            env = min(amp, env + amp / atk)
        else:
            env = amp * math.exp(-(i - atk) / (decay * SR))
        f = freq * (1.0 + detune)
        sample = 0.0
        for h, weight in enumerate(harmonics, start=1):
            sample += weight * math.sin(two_pi * f * h * t)
        buf[n0 + i] += sample * env


def noise_burst(buf: list, start: float, dur: float, amp: float, cutoff: float) -> None:
    n0 = int(start * SR)
    total = int(dur * SR)
    if n0 >= len(buf) or total <= 0:
        return
    total = min(total, len(buf) - n0)
    rnd = random.Random(7)
    raw = [rnd.uniform(-1.0, 1.0) for _ in range(total)]
    filt = highpass(raw, cutoff)
    for i in range(total):
        buf[n0 + i] += filt[i] * amp * math.exp(-i / (0.045 * SR))


def kick(buf: list, start: float, amp: float = 0.55) -> None:
    n0 = int(start * SR)
    total = int(0.28 * SR)
    if n0 >= len(buf):
        return
    total = min(total, len(buf) - n0)
    phase = 0.0
    for i in range(total):
        t = i / SR
        f = 48.0 + 78.0 * math.exp(-t * 34.0)
        phase += 2.0 * math.pi * f / SR
        buf[n0 + i] += math.sin(phase) * amp * math.exp(-t * 12.0)


def whoosh(buf: list, start: float, dur: float = 0.55, amp: float = 0.16) -> None:
    """转场用的上升气流。"""
    n0 = int(start * SR)
    total = int(dur * SR)
    if n0 >= len(buf):
        return
    total = min(total, len(buf) - n0)
    rnd = random.Random(23)
    raw = [rnd.uniform(-1.0, 1.0) for _ in range(total)]
    filt = highpass(raw, 900.0)
    for i in range(total):
        p = i / max(1, total)
        shape = math.sin(math.pi * p) ** 2
        buf[n0 + i] += filt[i] * amp * shape


def build(duration: float, marks) -> list:
    n = int(duration * SR)
    pad = [0.0] * n
    bass = [0.0] * n
    arp = [0.0] * n
    perc = [0.0] * n

    bars = int(duration / BAR) + 1
    for bar in range(bars):
        chord = CHORDS[bar % len(CHORDS)]
        t0 = bar * BAR
        # pad：三个音，慢起慢落
        for v, f in enumerate(chord):
            note(pad, t0, BAR * 1.05, f, 0.085, 0.9, 2.2,
                 harmonics=(1.0, 0.32, 0.14), detune=0.0015 * (v - 1))
            note(pad, t0, BAR * 1.05, f * 2, 0.028, 1.1, 1.8,
                 harmonics=(1.0, 0.22), detune=-0.002 * (v - 1))
        # 低音：每小节根音 + 第二拍五音
        note(bass, t0, BAR * 0.62, chord[0] / 2, 0.26, 0.03, 0.55, harmonics=(1.0, 0.18))
        note(bass, t0 + BEAT * 2, BEAT * 1.6, chord[0] / 2, 0.16, 0.02, 0.35, harmonics=(1.0, 0.12))
        # 琶音：八分音符，循环和弦音（两个八度）
        pattern = [0, 1, 2, 1, 2, 1, 0, 1]
        for k, idx in enumerate(pattern):
            f = chord[idx % 3] * (4.0 if idx >= 3 else 2.0)
            start = t0 + k * (BEAT / 2)
            if start >= duration:
                break
            pan = 0.25 if k % 2 == 0 else -0.25
            note(arp, start, 0.42, f, 0.055, 0.005, 0.16,
                 harmonics=(1.0, 0.45, 0.18, 0.08))
        # 打击：底鼓在 1、3 拍，弱 hi-hat 在反拍
        kick(perc, t0)
        kick(perc, t0 + BEAT * 2, 0.42)
        for k in range(4):
            noise_burst(perc, t0 + BEAT * k + BEAT / 2, 0.06, 0.05, 6000)

    pad_lp = lowpass(pad, 2600)
    arp_lp = lowpass(arp, 5200)
    noise = highpass(pad_lp, 120.0)

    mix = [0.0] * n
    for i in range(n):
        mix[i] = pad_lp[i] + noise[i] * 0.5 + bass[i] + arp_lp[i] + perc[i]

    for mark in marks:
        whoosh(mix, mark)

    wet = reverb(mix, 0.30)
    out = [0.0] * n
    for i in range(n):
        out[i] = mix[i] * 0.78 + wet[i]
    return out


def write_wav(path: str, mono: list, sr: int = SR) -> None:
    n = len(mono)
    # 立体声：右声道加一点 Haas 延时，做出宽度
    delay = int(0.012 * sr)
    peak = 0.0
    for v in mono:
        av = abs(v)
        if av > peak:
            peak = av
    gain = 0.92 / peak if peak > 0 else 1.0
    frames = bytearray()
    two_pi = 2.0 * math.pi
    for i in range(n):
        v = mono[i] * gain
        if v != v or v in (float("inf"), float("-inf")):
            v = 0.0
        left = math.tanh(v * 1.15)
        right_src = mono[i - delay] if i >= delay else 0.0
        right = math.tanh(right_src * gain * 1.12)
        frames += struct.pack("<hh", int(max(-1.0, min(1.0, left)) * 32000),
                              int(max(-1.0, min(1.0, right)) * 32000))
    with wave.open(path, "wb") as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        wf.writeframes(bytes(frames))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=36.6)
    parser.add_argument("--out", default="promo/bgm.wav")
    parser.add_argument("--marks", default="", help="转场时间点，逗号分隔")
    args = parser.parse_args(argv)

    marks = [float(x) for x in args.marks.split(",") if x.strip()]
    print("合成配乐：%.1f 秒，%d 个转场点" % (args.duration, len(marks)), flush=True)
    mono = build(args.duration, marks)
    write_wav(args.out, mono)
    print("已写入 %s（%.1f MB）" % (args.out, os.path.getsize(args.out) / 1024 / 1024), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
