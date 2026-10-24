#!/usr/bin/env python3
"""把 promo/scenes.html 的 8 个场景渲染成宣传片（带真实动画 + BGM）。

    python promo/build.py              # 全流程：抓帧 -> 编码 -> 配乐 -> 混流
    python promo/build.py --no-audio   # 只出无声版
    python promo/build.py --scene 5    # 只重做第 5 幕

用 Chrome DevTools Protocol 直连抓帧（promo/cdp.py，纯标准库），
比逐次启动 Chrome 快一个量级；每一帧都由 __setT(t) 回溯时间轴，保证确定性。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from cdp import Chrome  # noqa: E402

SCENES_HTML = os.path.join(HERE, "scenes.html")
FRAMES = os.path.join(HERE, "frames")
OUT = os.path.join(HERE, "dsh-code-quarantine-promo.mp4")
BGM = os.path.join(HERE, "bgm.wav")

W, H = 1920, 1080
FPS = 24
# 每幕时长（秒）：按内容节奏排，长的留给信息量大的场景
DURATIONS = {1: 4.2, 2: 5.0, 3: 4.2, 4: 4.6, 5: 5.0, 6: 4.4, 7: 4.6, 8: 4.6}

FFMPEG_CANDIDATES = ["ffmpeg", r"D:\ffmpeg-7.1.1-essentials_build\bin\ffmpeg.exe",
                      "/usr/bin/ffmpeg", "/opt/homebrew/bin/ffmpeg"]


def find_ffmpeg() -> str:
    for cand in FFMPEG_CANDIDATES:
        if os.path.isabs(cand):
            if os.path.isfile(cand):
                return cand
        else:
            found = shutil.which(cand)
            if found:
                return found
    raise SystemExit("找不到 ffmpeg")


def scene_url(n: int) -> str:
    return "file:///" + SCENES_HTML.replace("\\", "/").lstrip("/") + "?n=%d" % n


def capture(chrome: Chrome, scenes, fps: int) -> int:
    total = 0
    for n in scenes:
        hold = DURATIONS[n]
        frames = int(round(hold * fps))
        outdir = os.path.join(FRAMES, "s%d" % n)
        os.makedirs(outdir, exist_ok=True)
        chrome.open(scene_url(n))
        time.sleep(0.35)
        chrome.evaluate("window.__setT(0)")
        t0 = time.time()
        for i in range(frames):
            t = i / float(fps)
            chrome.evaluate("window.__setT(%f)" % t)
            chrome.shot(os.path.join(outdir, "f%04d.png" % i))
            if i % 24 == 0:
                pct = (i + 1) * 100 // frames
                print("  幕 %d: %3d%% (%d/%d 帧) %.0fs" % (n, pct, i + 1, frames, time.time() - t0), flush=True)
        print("幕 %d 完成：%d 帧 / %.1fs" % (n, frames, time.time() - t0), flush=True)
        total += frames
    return total


def encode(ffmpeg: str, scenes, fps: int, out: str) -> str:
    """把各幕的帧序列编码后拼成一条视频。"""
    tmp = out + ".video.mp4"
    for n in scenes:
        part = os.path.join(FRAMES, "s%d" % n)
        clip = os.path.join(FRAMES, "s%d.mp4" % n)
        cmd = [
            ffmpeg, "-y", "-framerate", str(fps), "-i", os.path.join(part, "f%04d.png"),
            "-c:v", "libx264", "-preset", "medium", "-crf", "18",
            "-color_range", "pc", "-colorspace", "bt709",
            "-color_primaries", "bt709", "-color_trc", "bt709",
            "-x264-params", "range=pc:colorspace=bt709",
            "-pix_fmt", "yuv420p", "-r", str(fps), clip,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise SystemExit("第 %d 幕编码失败：\n%s" % (n, proc.stderr[-1500:]))
    listfile = os.path.join(FRAMES, "list.txt")
    with open(listfile, "w", encoding="utf-8") as fh:
        for n in scenes:
            fh.write("file '%s'\n" % os.path.join(FRAMES, "s%d.mp4" % n).replace("\\", "/"))
    cmd = [ffmpeg, "-y", "-f", "concat", "-safe", "0", "-i", listfile, "-c:v", "copy", tmp]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("拼接失败：\n%s" % proc.stderr[-1500:])
    return tmp


def make_bgm(duration: float, marks) -> str:
    cmd = [sys.executable, os.path.join(HERE, "make_bgm.py"),
           "--duration", "%.2f" % duration, "--out", BGM,
           "--marks", ",".join("%.2f" % m for m in marks)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-500:])
        print(proc.stderr[-800:], file=sys.stderr)
        raise SystemExit("配乐生成失败")
    return BGM


def mux(ffmpeg: str, video: str, audio: str, out: str) -> str:
    cmd = [ffmpeg, "-y", "-i", video, "-i", audio,
           "-c:v", "copy", "-c:a", "aac", "-b:a", "160k", "-ar", "44100",
           "-shortest", "-movflags", "+faststart", out]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("混流失败：\n%s" % proc.stderr[-1500:])
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fps", type=int, default=FPS)
    parser.add_argument("--scene", type=int, help="只重做某一幕")
    parser.add_argument("--no-audio", action="store_true")
    parser.add_argument("--keep-frames", action="store_true")
    args = parser.parse_args(argv)

    ffmpeg = find_ffmpeg()
    scenes = [args.scene] if args.scene else list(range(1, 9))
    os.makedirs(FRAMES, exist_ok=True)

    total_seconds = sum(DURATIONS[n] for n in scenes)
    print("场景 %s，%d fps，共 %.1f 秒" % (scenes, args.fps, total_seconds), flush=True)

    with Chrome(width=W, height=H) as chrome:
        capture(chrome, scenes, args.fps)

    video = encode(ffmpeg, scenes, args.fps, OUT)

    if not args.no_audio and not args.scene:
        print("生成配乐…", flush=True)
        # 转场点：每幕的起始时刻（除第一幕）
        marks, acc = [], 0.0
        for n in scenes:
            acc += DURATIONS[n]
            if acc < total_seconds - 0.5:
                marks.append(acc)
        audio = make_bgm(total_seconds, marks)
        mux(ffmpeg, video, audio, OUT)
    else:
        shutil.copyfile(video, OUT)
    os.remove(video)

    size = os.path.getsize(OUT) / 1024 / 1024
    print("\n成片：%s（%.1f MB，%.1f 秒）" % (OUT, size, total_seconds), flush=True)

    if not args.keep_frames and not args.scene:
        shutil.rmtree(FRAMES, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
