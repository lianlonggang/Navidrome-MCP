/**
 * Regression coverage for the loopback-gated privileged web-UI routes and the
 * cover-art content-type allowlist. These surfaces are security-relevant and
 * previously had zero tests:
 *
 *  - health.ts     — /healthz must 404 (hide its version fingerprint) for any
 *                    non-loopback peer whenever the server is LAN-reachable,
 *                    which is true for BOTH `expose=true` AND a wildcard
 *                    `host==='0.0.0.0'` bind (the latter regressed before).
 *  - player.ts     — settings/shutdown routes must reject non-loopback peers
 *                    with 404, and the settings writer must merge (never
 *                    clobber) unrelated `webui` keys and other stored settings
 *                    (credentials included).
 *  - cover.ts      — a 200 upstream with a non-allowlisted content-type must be
 *                    rejected (stored-XSS defense) and its body cancelled so the
 *                    fetch connection is released.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Config } from '../../../src/config.js';
import type { SettingsFile } from '../../../src/config/store.js';
import { makeTestConfig } from '../../helpers/test-config.js';

// Mock the settings store: keep the REAL SettingsFileSchema (player.ts validates
// the merged object against it before writing) but stub the disk I/O so tests
// neither read nor write the real store.
vi.mock('../../../src/config/store.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/store.js')>();
  return { ...actual, readSettings: vi.fn(), writeSettings: vi.fn() };
});

// Mock the live persist flag so the response is deterministic and setPersist is
// observable.
vi.mock('../../../src/web/player-runtime.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/web/player-runtime.js')>();
  return { ...actual, getPersist: vi.fn(() => false), setPersist: vi.fn() };
});

// Mock the network fetch used by the cover proxy so no real HTTP is issued.
vi.mock('../../../src/utils/fetch-with-timeout.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/utils/fetch-with-timeout.js')>();
  return {
    ...actual,
    fetchWithTimeout: vi.fn(),
    getNavidromeRequestTimeoutMs: vi.fn(() => 5000),
  };
});

import { readSettings, writeSettings } from '../../../src/config/store.js';
import { getPersist, setPersist } from '../../../src/web/player-runtime.js';
import { fetchWithTimeout } from '../../../src/utils/fetch-with-timeout.js';
import { HEALTH_APP_ID, handleHealth } from '../../../src/webui/routes/health.js';
import {
  handleGetPlayerSettings,
  handleSetPlayerSettings,
  handleShutdown,
} from '../../../src/webui/routes/player.js';
import { handleCover } from '../../../src/webui/routes/cover.js';

/** Capture status + body written to a ServerResponse without a real socket. */
interface CapturedRes {
  res: ServerResponse;
  status: () => number | undefined;
  json: () => unknown;
}

function fakeRes(): CapturedRes {
  let status: number | undefined;
  let body = '';
  const res = {
    writableEnded: false,
    writeHead(code: number): ServerResponse {
      status = code;
      return res;
    },
    end(chunk?: string): void {
      if (typeof chunk === 'string') body += chunk;
    },
  } as unknown as ServerResponse;
  return {
    res,
    status: () => status,
    json: () => (body === '' ? undefined : JSON.parse(body)),
  };
}

/** IncomingMessage stand-in with a fixed peer address and an optional JSON body. */
function fakeReq(remoteAddress: string, bodyChunks: Buffer[] = []): IncomingMessage {
  const emitter = new EventEmitter() as IncomingMessage & {
    socket: { remoteAddress: string };
  };
  emitter.socket = { remoteAddress } as never;
  queueMicrotask(() => {
    for (const c of bodyChunks) emitter.emit('data', c);
    emitter.emit('end');
  });
  return emitter;
}

function configWith(webui: { expose: boolean; host: string }): Config {
  return makeTestConfig({
    webui: {
      enabled: true,
      host: webui.host,
      port: 8808,
      expose: webui.expose,
      autoOpenBrowser: false,
      persistAfterMcpExit: false,
    },
  });
}

const LOOPBACK = '127.0.0.1';
const LAN_PEER = '203.0.113.5';

afterEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
});

describe('handleHealth loopback gate (expose/host matrix)', () => {
  it('serves 200 to a non-loopback peer when not LAN-reachable (expose=false, host=127.0.0.1)', () => {
    const cap = fakeRes();
    handleHealth(fakeReq(LAN_PEER), cap.res, configWith({ expose: false, host: '127.0.0.1' }));
    expect(cap.status()).toBe(200);
    expect((cap.json() as { app: string }).app).toBe(HEALTH_APP_ID);
  });

  it('hides itself (404) from a non-loopback peer when expose=true', () => {
    const cap = fakeRes();
    handleHealth(fakeReq(LAN_PEER), cap.res, configWith({ expose: true, host: '127.0.0.1' }));
    expect(cap.status()).toBe(404);
  });

  it('serves 200 to a loopback peer even when expose=true', () => {
    const cap = fakeRes();
    handleHealth(fakeReq(LOOPBACK), cap.res, configWith({ expose: true, host: '127.0.0.1' }));
    expect(cap.status()).toBe(200);
  });

  it('hides itself (404) from a non-loopback peer on a wildcard bind (host=0.0.0.0, expose=false)', () => {
    // Regression guard: a 0.0.0.0 bind is LAN-reachable even with expose=false,
    // so the version fingerprint must still be gated to loopback.
    const cap = fakeRes();
    handleHealth(fakeReq(LAN_PEER), cap.res, configWith({ expose: false, host: '0.0.0.0' }));
    expect(cap.status()).toBe(404);
  });

  it('serves 200 to a loopback peer on a wildcard bind (host=0.0.0.0)', () => {
    const cap = fakeRes();
    handleHealth(fakeReq('::1'), cap.res, configWith({ expose: false, host: '0.0.0.0' }));
    expect(cap.status()).toBe(200);
  });
});

describe('player routes reject non-loopback peers', () => {
  it('handleGetPlayerSettings returns 404 to a LAN peer without reading the store', () => {
    const cap = fakeRes();
    handleGetPlayerSettings(fakeReq(LAN_PEER), cap.res);
    expect(cap.status()).toBe(404);
    expect(readSettings).not.toHaveBeenCalled();
  });

  it('handleSetPlayerSettings returns 404 to a LAN peer and never writes', async () => {
    const cap = fakeRes();
    await handleSetPlayerSettings(
      fakeReq(LAN_PEER, [Buffer.from(JSON.stringify({ autoOpenBrowser: true }))]),
      cap.res,
    );
    expect(cap.status()).toBe(404);
    expect(setPersist).not.toHaveBeenCalled();
    expect(writeSettings).not.toHaveBeenCalled();
  });

  it('handleShutdown returns 404 to a LAN peer and never invokes the shutdown callback', () => {
    const cap = fakeRes();
    const shutdown = vi.fn();
    handleShutdown(fakeReq(LAN_PEER), cap.res, shutdown);
    expect(cap.status()).toBe(404);
    expect(shutdown).not.toHaveBeenCalled();
  });

  it('handleShutdown accepts a loopback peer (200) and defers the callback', () => {
    vi.useFakeTimers();
    const cap = fakeRes();
    const shutdown = vi.fn();
    handleShutdown(fakeReq(LOOPBACK), cap.res, shutdown);
    expect(cap.status()).toBe(200);
    expect(shutdown).not.toHaveBeenCalled(); // deferred, not synchronous
    vi.advanceTimersByTime(50);
    expect(shutdown).toHaveBeenCalledTimes(1);
  });
});

describe('handleSetPlayerSettings preserves unrelated stored settings', () => {
  it('merges only the touched webui key, keeping credentials and other keys intact', async () => {
    const stored: SettingsFile = {
      navidrome: { url: 'http://music.local', username: 'admin', password: 'super-secret' },
      webui: {
        enabled: true,
        host: '0.0.0.0',
        port: 9000,
        expose: true,
        autoOpenBrowser: false,
        persistAfterMcpExit: true,
      },
      advanced: { debug: true },
    };
    vi.mocked(readSettings).mockReturnValue(stored);
    let written: SettingsFile | undefined;
    vi.mocked(writeSettings).mockImplementation((s) => {
      written = s;
    });

    const cap = fakeRes();
    await handleSetPlayerSettings(
      fakeReq(LOOPBACK, [Buffer.from(JSON.stringify({ autoOpenBrowser: true }))]),
      cap.res,
    );

    expect(cap.status()).toBe(200);
    expect(writeSettings).toHaveBeenCalledTimes(1);
    // The one touched key changed...
    expect(written?.webui?.autoOpenBrowser).toBe(true);
    // ...while every unrelated key survived the read-merge-write.
    expect(written?.webui?.host).toBe('0.0.0.0');
    expect(written?.webui?.port).toBe(9000);
    expect(written?.webui?.expose).toBe(true);
    expect(written?.webui?.persistAfterMcpExit).toBe(true);
    expect(written?.navidrome?.password).toBe('super-secret');
    expect(written?.advanced?.debug).toBe(true);
    // Body didn't touch persistAfterMcpExit, so the live flag isn't flipped.
    expect(setPersist).not.toHaveBeenCalled();
    expect(getPersist).toHaveBeenCalled();
  });
});

describe('handleCover content-type allowlist', () => {
  it('rejects a 200 upstream with a non-image content-type and cancels the body', async () => {
    const cancel = vi.fn().mockResolvedValue(undefined);
    const upstream = {
      ok: true,
      status: 200,
      body: { cancel } as unknown as ReadableStream<Uint8Array>,
      headers: {
        get: (name: string): string | null =>
          name.toLowerCase() === 'content-type' ? 'text/html; charset=utf-8' : null,
      },
    } as unknown as Response;
    vi.mocked(fetchWithTimeout).mockResolvedValue(upstream);

    const cap = fakeRes();
    await handleCover(cap.res, makeTestConfig(), 'album123');

    expect(cap.status()).toBe(502);
    expect((cap.json() as { error: string }).error).toContain('non-image');
    // The rejected upstream stream must be released, not leaked.
    expect(cancel).toHaveBeenCalledTimes(1);
  });
});
