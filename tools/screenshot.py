"""Render docs/demo.png from a real run against the local demo servers.

pip install -e ".[dev]" && playwright install chromium
python tools/screenshot.py
"""

from __future__ import annotations

import html
import re
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo.png"
sys.path.insert(0, str(Path(__file__).resolve().parent))

import demo_server  # noqa: E402

from tlswatch import cli  # noqa: E402

COLOURS = {"A": "ok", "B": "ok", "C": "warn", "D": "warn", "F": "bad"}


def colour(line: str) -> str:
    text = html.escape(line)
    text = re.sub(
        r"^(\S+:\d+)  grade (\w)",
        lambda m: (
            f'<span class="host">{m.group(1)}</span>  grade <span class="{COLOURS.get(m.group(2), "dim")}">{m.group(2)}</span>'
        ),
        text,
    )
    text = re.sub(
        r"\[(critical|high|medium|low|info)( *)\]",
        lambda m: f'[<span class="{m.group(1)}">{m.group(1)}</span>{m.group(2)}]',
        text,
    )
    text = re.sub(
        r"^(  )(certificate|trust|negotiated|protocols|weak ciphers)",
        r'\1<span class="dim">\2</span>',
        text,
    )
    return text


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        started = demo_server.build(directory)
        try:
            import contextlib
            import io

            # Show the host names rather than 127.0.0.1:port, as a real run would.
            # Four hosts keep the picture a readable size; the other three behave as described in the docs.
            keep = (
                "www.example.test",
                "shop.example.test",
                "expired.example.test",
                "dev.example.test",
            )
            toml = (directory / "hosts.toml").read_text(encoding="utf-8")
            head, *blocks = toml.split("[[hosts]]")
            chosen = [b for b in blocks if any(f'"{name}"' in b for name in keep)]
            (directory / "hosts.toml").write_text(
                head + "".join("[[hosts]]" + b for b in chosen), encoding="utf-8"
            )
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli.main(["check", "-c", str(directory / "hosts.toml"), "--no-ciphers"])
            text = out.getvalue()
            for label, server in started:
                text = text.replace(f"127.0.0.1:{server.port}", f"{label}:443")
        finally:
            for _, server in started:
                server.__exit__(None, None, None)
    lines = text.rstrip().splitlines()
    body = "\n".join(colour(line) for line in lines)
    page = f"""<html><body style="margin:0;background:#0d1117">
<div style="width:1000px;padding:22px 26px;box-sizing:border-box;background:#0d1117;color:#c9d1d9;font:13px/1.45 'DejaVu Sans Mono',Consolas,monospace">
<div style="color:#8b949e;margin-bottom:10px">$ tlswatch check -c hosts.toml</div>
<pre style="margin:0;font:inherit;white-space:pre">{body}</pre></div>
<style>.ok{{color:#3fb950}}.warn{{color:#d29922}}.bad{{color:#f85149}}.dim{{color:#8b949e}}.host{{color:#58a6ff;font-weight:bold}}
.critical{{color:#f85149}}.high{{color:#ff7b72}}.medium{{color:#d29922}}.low{{color:#e3b341}}.info{{color:#8b949e}}</style></body></html>"""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        shot = browser.new_page(viewport={"width": 1000, "height": 600}, device_scale_factor=2)
        shot.set_content(page)
        height = shot.evaluate("document.body.scrollHeight")
        shot.set_viewport_size({"width": 1000, "height": int(height)})
        OUT.parent.mkdir(exist_ok=True)
        shot.screenshot(path=str(OUT))
        browser.close()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
