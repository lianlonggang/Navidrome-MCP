/**
 * Navidrome MCP Server - Web UI Snapshot Routes
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

import type { ServerResponse } from 'node:http';
import type { NavidromeClient } from '../../client/navidrome-client.js';
import { getPlayQueue, nowPlaying } from '../../tools/playback.js';
import { runAction } from '../http-helpers.js';

/**
 * GET /api/now-playing — JSON form of the same `now_playing` MCP tool result.
 * Idempotent / cacheless. Used for first-paint and as a fallback if the SSE
 * stream is briefly unavailable.
 */
export async function handleNowPlaying(
  res: ServerResponse,
  client: NavidromeClient,
): Promise<void> {
  // Pass the client so now_playing can resolve title/artist/album by songId
  // after an MCP restart (empty engine cache), matching handleQueue.
  return runAction(res, () => nowPlaying({}, client));
}

/**
 * GET /api/queue — JSON form of `get_play_queue`.
 */
export async function handleQueue(
  res: ServerResponse,
  client: NavidromeClient,
): Promise<void> {
  return runAction(res, () => getPlayQueue(client, {}));
}
