const config = require('../config');
const { redis, isConnected } = require('./redis');

const KEYS = config.redisKeys;

// Local cache for usernames (reduces Redis roundtrips for frequent lookups)
const uuidUsernameCache = new Map();

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

/**
 * Register a new game session
 */
async function registerSession(sessionToken, uuid, username, serverAudience = null) {
  const sessionData = {
    uuid,
    username,
    serverAudience,
    createdAt: new Date().toISOString()
  };

  if (isConnected()) {
    try {
      await redis.setex(`${KEYS.SESSION}${sessionToken}`, config.sessionTtl, JSON.stringify(sessionData));

      if (serverAudience) {
        const previousServer = await redis.get(`${KEYS.PLAYER_SERVER}${uuid}`);
        if (previousServer && previousServer !== serverAudience) {
          await redis.srem(`${KEYS.SERVER_PLAYERS}${previousServer}`, uuid);
          console.log(`Player ${uuid} moved from server ${previousServer} to ${serverAudience}`);
        }

        await redis.sadd(`${KEYS.SERVER_PLAYERS}${serverAudience}`, uuid);
        await redis.setex(`${KEYS.PLAYER_SERVER}${uuid}`, config.sessionTtl, serverAudience);
      }

      if (username && username !== 'Player') {
        await redis.set(`${KEYS.USERNAME}${uuid}`, username);
        uuidUsernameCache.set(uuid, username);
      }

      console.log(`Session registered: ${uuid} (${username}) on server ${serverAudience || 'unknown'}`);
    } catch (e) {
      console.error('Failed to register session in Redis:', e.message);
    }
  }
}

/**
 * Register an auth grant (player joining a server)
 */
async function registerAuthGrant(authGrant, playerUuid, playerName, serverAudience) {
  const grantData = {
    playerUuid,
    playerName,
    serverAudience,
    createdAt: new Date().toISOString()
  };

  if (isConnected()) {
    try {
      await redis.setex(`${KEYS.AUTH_GRANT}${authGrant}`, config.sessionTtl, JSON.stringify(grantData));

      const previousServer = await redis.get(`${KEYS.PLAYER_SERVER}${playerUuid}`);
      if (previousServer && previousServer !== serverAudience) {
        await redis.srem(`${KEYS.SERVER_PLAYERS}${previousServer}`, playerUuid);
        console.log(`Player ${playerUuid} moved from server ${previousServer} to ${serverAudience}`);
      }

      await redis.sadd(`${KEYS.SERVER_PLAYERS}${serverAudience}`, playerUuid);
      await redis.setex(`${KEYS.PLAYER_SERVER}${playerUuid}`, config.sessionTtl, serverAudience);

      await persistUsername(playerUuid, playerName);

      console.log(`Auth grant registered: ${playerUuid} (${playerName}) -> server ${serverAudience}`);
    } catch (e) {
      console.error('Failed to register auth grant in Redis:', e.message);
    }
  }
}

/**
 * Remove a session
 */
async function removeSession(sessionToken) {
  if (!isConnected()) return false;

  try {
    const sessionJson = await redis.get(`${KEYS.SESSION}${sessionToken}`);
    if (!sessionJson) return false;

    const session = JSON.parse(sessionJson);

    if (session.serverAudience) {
      await redis.srem(`${KEYS.SERVER_PLAYERS}${session.serverAudience}`, session.uuid);

      const remaining = await redis.scard(`${KEYS.SERVER_PLAYERS}${session.serverAudience}`);
      if (remaining === 0) {
        await redis.del(`${KEYS.SERVER_PLAYERS}${session.serverAudience}`);
      }
    }

    await redis.del(`${KEYS.PLAYER_SERVER}${session.uuid}`);
    await redis.del(`${KEYS.SESSION}${sessionToken}`);

    console.log(`Session removed: ${session.uuid} (${session.username})`);
    return true;
  } catch (e) {
    console.error('Failed to remove session:', e.message);
    return false;
  }
}

// ============================================================================
// PLAYER/SERVER QUERIES
// ============================================================================

/**
 * Get players on a specific server
 */
async function getPlayersOnServer(serverAudience) {
  if (!isConnected()) return [];

  try {
    const playerUuids = await redis.smembers(`${KEYS.SERVER_PLAYERS}${serverAudience}`);
    if (!playerUuids || playerUuids.length === 0) return [];

    const players = [];
    for (const uuid of playerUuids) {
      let username = uuidUsernameCache.get(uuid);
      if (!username) {
        username = await redis.get(`${KEYS.USERNAME}${uuid}`);
        if (username) {
          uuidUsernameCache.set(uuid, username);
        }
      }
      players.push({
        uuid,
        username: username || `Player_${uuid.substring(0, 8)}`
      });
    }
    return players;
  } catch (e) {
    console.error('Failed to get players on server:', e.message);
    return [];
  }
}

/**
 * Find player by username on a specific server
 */
async function findPlayerOnServer(serverAudience, username) {
  const players = await getPlayersOnServer(serverAudience);
  return players.filter(p => p.username.toLowerCase() === username.toLowerCase());
}

/**
 * Get all active sessions
 */
async function getAllActiveSessions() {
  if (!isConnected()) return { sessions: [], servers: [] };

  try {
    const sessionKeys = await redis.keys(`${KEYS.SESSION}*`);
    const sessions = [];
    const playerTtls = new Map();

    for (const key of sessionKeys) {
      const sessionJson = await redis.get(key);
      if (sessionJson) {
        const session = JSON.parse(sessionJson);
        session.token = key.replace(KEYS.SESSION, '').substring(0, 8) + '...';

        const ttl = await redis.ttl(key);
        session.ttl = ttl;
        session.ttlMinutes = Math.round(ttl / 60);
        session.ttlHours = Math.round(ttl / 3600 * 10) / 10;

        if (!playerTtls.has(session.uuid) || ttl > playerTtls.get(session.uuid)) {
          playerTtls.set(session.uuid, ttl);
        }

        sessions.push(session);
      }
    }

    const validPlayerUuids = new Set(sessions.map(s => s.uuid));

    const serverKeys = await redis.keys(`${KEYS.SERVER_PLAYERS}*`);
    const servers = [];

    for (const key of serverKeys) {
      const serverAudience = key.replace(KEYS.SERVER_PLAYERS, '');
      const playerUuids = await redis.smembers(key);

      const activePlayers = [];
      const staleUuids = [];

      for (const uuid of playerUuids) {
        if (validPlayerUuids.has(uuid)) {
          let username = uuidUsernameCache.get(uuid);
          if (!username) {
            username = await redis.get(`${KEYS.USERNAME}${uuid}`);
            if (username) {
              uuidUsernameCache.set(uuid, username);
            }
          }
          const ttl = playerTtls.get(uuid) || 0;
          activePlayers.push({
            uuid,
            username: username || `Player_${uuid.substring(0, 8)}`,
            ttl: ttl,
            ttlMinutes: Math.round(ttl / 60),
            ttlHours: Math.round(ttl / 3600 * 10) / 10
          });
        } else {
          staleUuids.push(uuid);
        }
      }

      if (staleUuids.length > 0) {
        for (const uuid of staleUuids) {
          await redis.srem(key, uuid);
        }
        console.log(`Cleaned ${staleUuids.length} stale players from server ${serverAudience}`);
      }

      if (activePlayers.length === 0) {
        await redis.del(key);
        console.log(`Removed empty server: ${serverAudience}`);
        continue;
      }

      let serverName = await getServerName(serverAudience);

      servers.push({
        audience: serverAudience,
        name: serverName,
        playerCount: activePlayers.length,
        players: activePlayers
      });
    }

    servers.sort((a, b) => b.playerCount - a.playerCount);

    return { sessions, servers };
  } catch (e) {
    console.error('Failed to get active sessions:', e.message);
    return { sessions: [], servers: [] };
  }
}

// ============================================================================
// SERVER NAME MANAGEMENT
// ============================================================================

/**
 * Get server display name from Redis
 */
async function getServerName(audience) {
  if (!audience || !isConnected()) return null;

  try {
    return await redis.get(`${KEYS.SERVER_NAME}${audience}`);
  } catch (e) {
    return null;
  }
}

/**
 * Set server display name in Redis
 */
async function setServerName(audience, name) {
  if (!audience || !name || !isConnected()) return false;

  try {
    await redis.set(`${KEYS.SERVER_NAME}${audience}`, name);
    console.log(`Server name set: ${audience} -> "${name}"`);
    return true;
  } catch (e) {
    console.error('Failed to set server name:', e.message);
    return false;
  }
}

// ============================================================================
// USER DATA
// ============================================================================

/**
 * Persist username to Redis
 */
async function persistUsername(uuid, name) {
  if (!uuid || !name || name === 'Player') return;

  uuidUsernameCache.set(uuid, name);

  if (isConnected()) {
    try {
      await redis.set(`${KEYS.USERNAME}${uuid}`, name);

      const userKey = `${KEYS.USER}${uuid}`;
      let userData = {};
      const existing = await redis.get(userKey);
      if (existing) {
        userData = JSON.parse(existing);
      }
      userData.username = name;
      userData.lastSeen = new Date().toISOString();
      await redis.set(userKey, JSON.stringify(userData));
    } catch (e) {
      console.error('Failed to persist username:', e.message);
    }
  }
}

/**
 * Get user data from Redis
 */
async function getUserData(uuid) {
  if (!isConnected()) return {};

  try {
    const data = await redis.get(`${KEYS.USER}${uuid}`);
    return data ? JSON.parse(data) : {};
  } catch (e) {
    console.error('Failed to get user data:', e.message);
    return {};
  }
}

/**
 * Save user data to Redis
 */
async function saveUserData(uuid, data) {
  if (!isConnected()) return;

  try {
    await redis.set(`${KEYS.USER}${uuid}`, JSON.stringify(data));
    if (data.username) {
      await redis.set(`${KEYS.USERNAME}${uuid}`, data.username);
      uuidUsernameCache.set(uuid, data.username);
    }
  } catch (e) {
    console.error('Failed to save user data:', e.message);
  }
}

/**
 * Get username from cache or Redis
 */
async function getUsername(uuid) {
  if (uuidUsernameCache.has(uuid)) {
    return uuidUsernameCache.get(uuid);
  }

  if (isConnected()) {
    try {
      const username = await redis.get(`${KEYS.USERNAME}${uuid}`);
      if (username) {
        uuidUsernameCache.set(uuid, username);
        return username;
      }
    } catch (e) {
      // Fall through to default
    }
  }

  return null;
}

/**
 * Get username from local cache only (sync)
 */
function getCachedUsername(uuid) {
  return uuidUsernameCache.get(uuid);
}

/**
 * Set username in local cache (sync)
 */
function setCachedUsername(uuid, username) {
  uuidUsernameCache.set(uuid, username);
}

// ============================================================================
// ADMIN STATS AND QUERIES
// ============================================================================

/**
 * Check if Redis is connected
 */
function isRedisConnected() {
  return isConnected();
}

/**
 * Get key counts for admin stats (optimized with SCAN)
 */
async function getKeyCounts() {
  const counts = { sessions: 0, authGrants: 0, users: 0, servers: 0, activePlayers: 0 };

  if (!isConnected()) return counts;

  try {
    // Use SCAN to count keys efficiently (non-blocking)
    const countKeys = async (pattern) => {
      let count = 0;
      let cursor = '0';
      do {
        const [newCursor, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 1000);
        cursor = newCursor;
        count += keys.length;
      } while (cursor !== '0');
      return count;
    };

    // Count keys in parallel
    const [sessions, authGrants, users, serverKeys] = await Promise.all([
      countKeys(`${KEYS.SESSION}*`),
      countKeys(`${KEYS.AUTH_GRANT}*`),
      countKeys(`${KEYS.USER}*`),
      (async () => {
        // For servers, we need to count and also get active players
        const keys = [];
        let cursor = '0';
        do {
          const [newCursor, foundKeys] = await redis.scan(cursor, 'MATCH', `${KEYS.SERVER_PLAYERS}*`, 'COUNT', 500);
          cursor = newCursor;
          keys.push(...foundKeys);
        } while (cursor !== '0');
        return keys;
      })()
    ]);

    counts.sessions = sessions;
    counts.authGrants = authGrants;
    counts.users = users;
    // Filter out hytale-client from server count
    counts.servers = serverKeys.filter(k => !k.endsWith('hytale-client')).length;

    // Get unique player count from server player sets (much faster than parsing sessions)
    // Use SCARD to get set sizes in parallel
    if (serverKeys.length > 0) {
      const playerCounts = await Promise.all(
        serverKeys
          .filter(k => !k.endsWith('hytale-client'))
          .map(key => redis.scard(key))
      );
      counts.activePlayers = playerCounts.reduce((sum, count) => sum + count, 0);
    }
  } catch (e) {
    console.error('Error getting key counts:', e.message);
  }

  return counts;
}

/**
 * Get paginated servers with players (for admin dashboard)
 */
async function getPaginatedServers(page, limit) {
  const offset = (page - 1) * limit;

  if (!isConnected()) {
    return {
      servers: [],
      pagination: { page, limit, totalServers: 0, totalPages: 0, hasNext: false, hasPrev: false },
      timestamp: new Date().toISOString()
    };
  }

  try {
    // Get all server keys using SCAN
    const serverKeys = [];
    let cursor = '0';
    do {
      const [newCursor, keys] = await redis.scan(cursor, 'MATCH', `${KEYS.SERVER_PLAYERS}*`, 'COUNT', 500);
      cursor = newCursor;
      serverKeys.push(...keys);
    } while (cursor !== '0');

    // Get player counts for all servers
    // Filter out 'hytale-client' which contains ALL players with valid tokens
    const serverCounts = (await Promise.all(serverKeys.map(async (key) => ({
      key,
      audience: key.replace(KEYS.SERVER_PLAYERS, ''),
      count: await redis.scard(key)
    })))).filter(s => s.audience !== 'hytale-client');

    // Sort by player count descending
    serverCounts.sort((a, b) => b.count - a.count);

    const totalServers = serverCounts.length;
    const totalPages = Math.ceil(totalServers / limit);

    // Get only the servers for this page
    const pageServers = serverCounts.slice(offset, offset + limit);

    // Fetch full details for this page's servers
    const servers = await Promise.all(pageServers.map(async ({ key, audience, count }) => {
      const [playerUuids, serverName] = await Promise.all([
        redis.smembers(key),
        redis.get(`${KEYS.SERVER_NAME}${audience}`)
      ]);

      // Get usernames and TTLs for players
      const players = await Promise.all(playerUuids.map(async (uuid) => {
        let username = uuidUsernameCache.get(uuid);

        const [usernameFromRedis, ttl] = await Promise.all([
          username ? Promise.resolve(null) : redis.get(`${KEYS.USERNAME}${uuid}`),
          redis.ttl(`${KEYS.PLAYER_SERVER}${uuid}`)
        ]);

        if (!username && usernameFromRedis) {
          username = usernameFromRedis;
          uuidUsernameCache.set(uuid, username);
        }

        return {
          uuid,
          username: username || `Player_${uuid.substring(0, 8)}`,
          ttl: ttl > 0 ? ttl : 0
        };
      }));

      return {
        audience,
        name: serverName,
        playerCount: count,
        players
      };
    }));

    return {
      servers,
      pagination: {
        page,
        limit,
        totalServers,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      },
      timestamp: new Date().toISOString()
    };
  } catch (e) {
    console.error('getPaginatedServers error:', e.message);
    return {
      servers: [],
      pagination: { page, limit, totalServers: 0, totalPages: 0, hasNext: false, hasPrev: false },
      error: e.message,
      timestamp: new Date().toISOString()
    };
  }
}

/**
 * Get all player UUIDs from all servers (for prerender queue)
 */
async function getAllPlayerUuids() {
  if (!isConnected()) return [];

  try {
    const serverKeys = [];
    let cursor = '0';
    do {
      const [newCursor, keys] = await redis.scan(cursor, 'MATCH', `${KEYS.SERVER_PLAYERS}*`, 'COUNT', 500);
      cursor = newCursor;
      serverKeys.push(...keys);
    } while (cursor !== '0');

    const allUuids = new Set();
    for (const key of serverKeys) {
      const uuids = await redis.smembers(key);
      uuids.forEach(uuid => allUuids.add(uuid));
    }

    return Array.from(allUuids);
  } catch (e) {
    console.error('Error getting all player UUIDs:', e.message);
    return [];
  }
}

// ============================================================================
// ADMIN TOKENS
// ============================================================================

/**
 * Create admin token
 */
async function createAdminToken(token) {
  if (!isConnected()) return false;

  try {
    await redis.setex(`${KEYS.ADMIN_TOKEN}${token}`, config.adminTokenTtl, '1');
    return true;
  } catch (e) {
    console.error('Failed to create admin token:', e.message);
    return false;
  }
}

/**
 * Verify admin token
 */
async function verifyAdminToken(token) {
  if (!token || !isConnected()) return false;

  try {
    const exists = await redis.exists(`${KEYS.ADMIN_TOKEN}${token}`);
    if (exists) {
      await redis.expire(`${KEYS.ADMIN_TOKEN}${token}`, config.adminTokenTtl);
      return true;
    }
    return false;
  } catch (e) {
    console.error('Redis error checking admin token:', e.message);
    return false;
  }
}

/**
 * Search players by username or UUID
 * Returns players with their server locations
 */
async function searchPlayers(query, limit = 50) {
  if (!query || !isConnected()) return [];

  query = query.toLowerCase().trim();
  if (query.length < 2) return []; // Minimum 2 chars

  try {
    // Get all server keys
    const serverKeys = await redis.keys(`${KEYS.SERVER_PLAYERS}*`);
    const results = new Map(); // uuid -> { uuid, username, servers: [] }

    for (const serverKey of serverKeys) {
      const serverAudience = serverKey.replace(KEYS.SERVER_PLAYERS, '');
      const playerUuids = await redis.smembers(serverKey);

      for (const uuid of playerUuids) {
        // Check UUID match first (fast)
        const uuidMatch = uuid.toLowerCase().includes(query);

        // Get username for this player
        let username = uuidUsernameCache.get(uuid);
        if (!username) {
          username = await redis.get(`${KEYS.USERNAME}${uuid}`);
          if (username) uuidUsernameCache.set(uuid, username);
        }
        username = username || 'Player';

        const nameMatch = username.toLowerCase().includes(query);

        if (uuidMatch || nameMatch) {
          if (results.has(uuid)) {
            // Player already found, add this server
            results.get(uuid).servers.push(serverAudience);
          } else {
            // Get TTL for player
            const ttl = await redis.ttl(`${KEYS.PLAYER_SERVER}${uuid}`);

            results.set(uuid, {
              uuid,
              username,
              ttl: ttl > 0 ? ttl : 0,
              servers: [serverAudience]
            });

            // Stop if we hit the limit
            if (results.size >= limit) break;
          }
        }
      }

      if (results.size >= limit) break;
    }

    // Convert to array and fetch server names
    const resultsArray = Array.from(results.values());

    // Get server names for all unique servers
    const allServerAudiences = new Set();
    for (const player of resultsArray) {
      for (const aud of player.servers) {
        allServerAudiences.add(aud);
      }
    }

    const serverNames = new Map();
    for (const aud of allServerAudiences) {
      const name = await redis.get(`${KEYS.SERVER_NAME}${aud}`);
      serverNames.set(aud, name || aud);
    }

    // Transform servers array to include names
    for (const player of resultsArray) {
      player.servers = player.servers.map(aud => ({
        audience: aud,
        name: serverNames.get(aud) || aud
      }));
    }

    return resultsArray;
  } catch (e) {
    console.error('Error searching players:', e.message);
    return [];
  }
}

// ============================================================================
// DEVICE CODE MANAGEMENT (OAuth Device Flow)
// ============================================================================

// In-memory store for device codes (short-lived, no need for Redis)
const deviceCodes = new Map();

/**
 * Register a device code for OAuth device flow
 */
function registerDeviceCode(deviceCode, userCode, clientId, scope) {
  const data = {
    deviceCode,
    userCode,
    clientId,
    scope,
    approved: false,
    createdAt: Date.now(),
    expiresAt: Date.now() + 600000  // 10 minutes
  };

  deviceCodes.set(deviceCode, data);
  deviceCodes.set(userCode, data);  // Also index by user code

  // Auto-cleanup expired codes
  setTimeout(() => {
    deviceCodes.delete(deviceCode);
    deviceCodes.delete(userCode);
  }, 600000);

  console.log(`Device code registered: ${userCode} (expires in 10 min)`);
  return data;
}

/**
 * Get device code data
 */
function getDeviceCode(deviceCode) {
  const data = deviceCodes.get(deviceCode);
  if (!data) return null;

  // Check expiry
  if (Date.now() > data.expiresAt) {
    deviceCodes.delete(deviceCode);
    deviceCodes.delete(data.userCode);
    return null;
  }

  return data;
}

/**
 * Approve a device code by user code
 */
function approveDeviceCode(userCode) {
  const data = deviceCodes.get(userCode);
  if (data) {
    data.approved = true;
    console.log(`Device code approved: ${userCode}`);
    return true;
  }
  return false;
}

/**
 * Consume (delete) a device code after token exchange
 */
function consumeDeviceCode(deviceCode) {
  const data = deviceCodes.get(deviceCode);
  if (data) {
    deviceCodes.delete(deviceCode);
    deviceCodes.delete(data.userCode);
    console.log(`Device code consumed: ${data.userCode}`);
    return true;
  }
  return false;
}

/**
 * Проверяет, есть ли активная сессия для UUID
 */
async function hasActiveSession(uuid) {
  if (!isConnected()) return false;

  try {
    const sessionKeys = await redis.keys(`${KEYS.SESSION}*`);

    for (const key of sessionKeys) {
      const sessionJson = await redis.get(key);
      if (sessionJson) {
        const session = JSON.parse(sessionJson);
        if (session.uuid === uuid) {
          return true;
        }
      }
    }

    return false;
  } catch (e) {
    console.error('Error checking active session:', e.message);
    return false;
  }
}

module.exports = {
  // Sessions
  registerSession,
  registerAuthGrant,
  removeSession,
  hasActiveSession,

  // Players/Servers
  getPlayersOnServer,
  findPlayerOnServer,
  getAllActiveSessions,

  // Server names
  getServerName,
  setServerName,

  // User data
  persistUsername,
  getUserData,
  saveUserData,
  getUsername,
  getCachedUsername,
  setCachedUsername,

  // Admin stats
  isRedisConnected,
  getKeyCounts,
  getPaginatedServers,
  getAllPlayerUuids,

  // Player search
  searchPlayers,

  // Admin tokens
  createAdminToken,
  verifyAdminToken,

  // Device codes (OAuth device flow)
  registerDeviceCode,
  getDeviceCode,
  approveDeviceCode,
  consumeDeviceCode,
};
