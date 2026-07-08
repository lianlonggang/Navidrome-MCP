/**
 * Navidrome MCP Server - Web UI Health Route
 * Copyright (C) 2025
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Config } from '../../config.js';
import { getPackageVersion } from '../../utils/version.js';
import { writeError, writeJson } from '../http-helpers.js';
import { isLoopbackPeer } from '../loopback.js';

/**
 * The signature `acquireOrAttach` (src/web/acquire.ts) probes to distinguish
 * *our* server from an unrelated process squatting the configured port. The
 * probe always uses loopback, so a foreign signature ⇒ port conflict.
 */
export const HEALTH_APP_ID = 'navidrome-mcp-web';

/**
 * GET /healthz — small JSON signature used for port-as-lock coexistence.
 *
 * When `expose=true` the player is reachable on the LAN, but /healthz leaks a
 * version fingerprint, so it is gated to loopback peers (returning 404 to hide
 * its existence). The acquire probe always connects via 127.0.0.1, so this
 * gate never interferes with coexistence.
 */
export function handleHealth(req: IncomingMessage, res: ServerResponse, config: Config): void {
  // LAN-reachability matches network-info.ts and main.ts's logBanner: either an
  // explicit expose, or a wildcard bind (`0.0.0.0`) that reaches the LAN even with
  // expose=false. Gate /healthz to loopback peers in either case so the version
  // fingerprint never leaks off-box.
  if ((config.webui.expose || config.webui.host === '0.0.0.0') && !isLoopbackPeer(req)) {
    writeError(res, 404, 'Not found');
    return;
  }
  writeJson(res, 200, { app: HEALTH_APP_ID, version: getPackageVersion() });
}
