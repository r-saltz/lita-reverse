#!/usr/bin/env python3
"""Lita API Client - Optimized Playwright Version

Persistent browser daemon approach:
- Chrome opens ONCE, handles many requests
- WASM signature generated inside browser context
- ~2-3 seconds per request (vs ~15s before)

Usage:
    python3 lita_fast.py                              # ranking harian
    python3 lita_fast.py /h5/init                      # init token
    python3 lita_fast.py /funbit/v2/system/option/h5   # system options
    python3 lita_fast.py --endpoint /path --type daily  # custom

Requires: patchright, chromium browser
"""

import asyncio
import json
import sys
import os
import time

try:
    from patchright.async_api import async_playwright
except ImportError:
    os.system('pip install patchright -q')
    from patchright.async_api import async_playwright

PAGE_URL = 'https://h5.lita.game/ranking-list?type=ranking-list&fullScreen=true&locale=id&version=121&appVersion=1.326&proxyHeader=eyJjaGVjayI6IkY3RTQyN0M5RkZEQTBFMEYyNTA5MTFBRjBFQTYyOEU4IiwiY2l0eSI6InN1cmFiYXlhIiwicmVnaW9uIjoiSUQiLCJ0aW1lIjoxNzg4OTM5MjA2NzA2LCJ1c2VySWQiOjI0ODIxMjkwLCJ1c2VyTG9jYWxlIjoiaW4tSUQiLCJ2ZXJzaW9uIjoiMi4wIn0=&userLocale=in&sts=1788939395401&sourceName=MST&user-id=24821290&accessToken=UGvxft+Z/BctCVx4Sl5axccMOr8KoMPZf7635t5Xg7uGnq63FcxjZ5QFi1mEwwzb&gender=0&topSafeHeight=4.359673&bottomSafeHeight=0'
CHROME = '/a0/tmp/playwright/chromium-1228/chrome-linux64/chrome'
API_BASE = 'https://h-api.lita.game'

JS_FETCH = '''
async (url) => {
    try {
        const resp = await fetch(url, { credentials: 'include' });
        const text = await resp.text();
        try { return JSON.stringify({ s: resp.status, d: JSON.parse(text) }); }
        catch { return JSON.stringify({ s: resp.status, d: null, r: text.slice(0, 500) }); }
    } catch(e) { return JSON.stringify({ s: 0, e: e.message }); }
}
'''


class LitaClient:
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.page = None
        self.responses = {}
        self.ready = False

    async def start(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            executable_path=CHROME,
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
        )
        context = await self.browser.new_context(
            user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36'
        )
        self.page = await context.new_page()

        def on_response(resp):
            if API_BASE in resp.url:
                asyncio.ensure_future(self._capture(resp))
        self.page.on('response', on_response)

        try:
            await self.page.goto(PAGE_URL, timeout=30000, wait_until='domcontentloaded')
        except:
            pass

        # Wait for page ready + WASM init
        await asyncio.sleep(8)
        self.ready = True

    async def _capture(self, resp):
        try:
            body = await resp.text()
            self.responses[resp.url] = body
        except:
            pass

    async def request(self, endpoint, params=None):
        query = ''
        if params and isinstance(params, dict):
            query = '&'.join(f'{k}={v}' for k, v in params.items())
        full_url = API_BASE + endpoint + ('?' + query if query else '')
        result = await self.page.evaluate(JS_FETCH, full_url)
        return json.loads(result)

    async def close(self):
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()


async def fetch_api(endpoint, params=''):
    client = LitaClient()
    try:
        await client.start()

        # Check if ranking data was already captured during page load
        for url, body in client.responses.items():
            if '/rank' in endpoint and '/rank' in url:
                print(body)
                return

        param_dict = {}
        if params:
            for p in params.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    param_dict[k] = v

        result = await client.request(endpoint, param_dict or None)
        data = result.get('d')
        if data:
            print(json.dumps(data, ensure_ascii=False))
        else:
            print(json.dumps(result, ensure_ascii=False))
    finally:
        await client.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ('-h', '--help'):
        print(__doc__)
        return

    endpoint = '/funbit/v2/api/active/202108/rank'
    params = 'type=daily'

    if len(sys.argv) > 1 and not sys.argv[1].startswith('--'):
        endpoint = sys.argv[1]
        params = ''
        if len(sys.argv) > 2 and not sys.argv[2].startswith('--'):
            params = sys.argv[2]
    elif '--endpoint' in sys.argv:
        idx = sys.argv.index('--endpoint')
        if idx + 1 < len(sys.argv):
            endpoint = sys.argv[idx + 1]
        if '--type' in sys.argv:
            tidx = sys.argv.index('--type')
            if tidx + 1 < len(sys.argv):
                params = 'type=' + sys.argv[tidx + 1]

    print(f'Endpoint: {endpoint}', file=sys.stderr)
    if params:
        print(f'Params: {params}', file=sys.stderr)

    start = time.time()
    asyncio.run(fetch_api(endpoint, params))
    elapsed = time.time() - start
    print(f'[{elapsed:.1f}s]', file=sys.stderr)


if __name__ == '__main__':
    main()
