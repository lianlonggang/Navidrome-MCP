/**
 * Pins the SSE dead-peer reaping. res.write() does NOT throw synchronously
 * when a peer's socket is gone (Node reports it via res.destroyed /
 * res.writableEnded), so the reaper must inspect those flags — an
 * exception-only check would let dead ServerResponse objects accumulate in the
 * client set for the process lifetime. These tests exercise the private
 * sendHeartbeat / writeToClient logic directly against fake responses.
 */

import { describe, expect, it } from 'vitest';
import type { ServerResponse } from 'node:http';
import { SseBroadcaster } from '../../../src/webui/broadcaster.js';

/** Minimal ServerResponse stand-in: only the fields the reaper touches. */
function fakeRes(opts: { destroyed?: boolean; writableEnded?: boolean } = {}): ServerResponse {
  return {
    destroyed: opts.destroyed ?? false,
    writableEnded: opts.writableEnded ?? false,
    // res.write() returning false is backpressure, NOT death — the reaper must
    // not treat it as a dead pipe. Return false here to pin that distinction.
    write: (): boolean => false,
  } as unknown as ServerResponse;
}

/** Reach the private members the reaping logic operates on. */
interface BroadcasterInternals {
  clients: Set<ServerResponse>;
  sendHeartbeat: () => void;
  writeToClient: (res: ServerResponse, json: string) => boolean;
}

function internals(b: SseBroadcaster): BroadcasterInternals {
  return b as unknown as BroadcasterInternals;
}

function newBroadcaster(): SseBroadcaster {
  // The constructor only stashes the client; nothing here touches it.
  return new SseBroadcaster({} as never);
}

describe('SseBroadcaster dead-peer reaping', () => {
  it('sendHeartbeat drops a client whose socket is already destroyed (peer RST)', () => {
    const b = newBroadcaster();
    const inner = internals(b);
    const dead = fakeRes({ destroyed: true });
    const live = fakeRes();
    inner.clients.add(dead);
    inner.clients.add(live);

    inner.sendHeartbeat();

    expect(inner.clients.has(dead)).toBe(false);
    expect(inner.clients.has(live)).toBe(true);
  });

  it('sendHeartbeat drops a client whose writable side has ended', () => {
    const b = newBroadcaster();
    const inner = internals(b);
    const ended = fakeRes({ writableEnded: true });
    inner.clients.add(ended);

    inner.sendHeartbeat();

    expect(inner.clients.has(ended)).toBe(false);
  });

  it('sendHeartbeat keeps a live client even when write() reports backpressure', () => {
    const b = newBroadcaster();
    const inner = internals(b);
    const live = fakeRes();
    inner.clients.add(live);

    inner.sendHeartbeat();

    expect(inner.clients.has(live)).toBe(true);
  });

  it('writeToClient reports failure for a destroyed socket instead of a phantom success', () => {
    const b = newBroadcaster();
    expect(internals(b).writeToClient(fakeRes({ destroyed: true }), '{}')).toBe(false);
  });

  it('writeToClient reports failure for a socket whose writable side has ended', () => {
    const b = newBroadcaster();
    expect(internals(b).writeToClient(fakeRes({ writableEnded: true }), '{}')).toBe(false);
  });

  it('writeToClient reports success for a live socket (backpressure is not death)', () => {
    const b = newBroadcaster();
    expect(internals(b).writeToClient(fakeRes(), '{}')).toBe(true);
  });
});
