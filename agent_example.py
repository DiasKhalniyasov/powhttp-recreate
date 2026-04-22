"""Sample agent: open a URL in headless Chromium, wait for idle, then query flows.

The point is to show the end-to-end loop. Replace this with your real agent
(Playwright script that logs in, scrolls, clicks, etc.); the capture pipeline
is identical.
"""

from __future__ import annotations

import asyncio
import os
import time

from playwright.async_api import async_playwright

import flows

TASK_URL = os.environ.get("TASK_URL", "https://httpbin.org/anything/hello")
PROXY_URL = os.environ.get("POWHTTP_PROXY_URL", "http://127.0.0.1:8888")


async def run_browser(url: str) -> None:
    # `launch` with a proxy config — Chromium forwards HTTP + HTTPS through mitmproxy.
    # NO `--ignore-certificate-errors`: the MITM CA is installed in the NSS DB, so the
    # cert chain validates like it would for a real CA. Upstream cert failures still surface.
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            proxy={"server": PROXY_URL},
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                # Force HTTP/2 fallback — mitmproxy doesn't speak h3 yet.
                "--disable-quic",
                # Keep proxy bypass for loopback so any local callbacks don't MITM themselves.
                "--proxy-bypass-list=<-loopback>",
            ],
        )
        try:
            ctx = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                ),
            )
            page = await ctx.new_page()
            print(f"[agent] navigating to {url}")
            await page.goto(url, wait_until="networkidle", timeout=30_000)
            # Give any late XHRs a moment to complete.
            await asyncio.sleep(1.0)
        finally:
            await browser.close()


def summarize_captured(since_ms: int) -> None:
    entries = flows.search_entries(since_ms=since_ms, limit=500)
    print(f"\n[agent] captured {len(entries)} requests since task start\n")
    for e in entries:
        status = e.status if e.status is not None else "ERR"
        print(f"  {e.method:6} {status}  {e.url}")

    print("\n[agent] endpoint clusters:")
    for row in flows.extract_endpoints(since_ms=since_ms):
        print(f"  {row['hits']:3}x  {row['method']:6} {row['remote_host']}  {row['example_url']}")


def main() -> None:
    task_start_ms = int(time.time() * 1000)
    asyncio.run(run_browser(TASK_URL))
    summarize_captured(task_start_ms)


if __name__ == "__main__":
    main()
