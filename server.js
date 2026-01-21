const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { execSync } = require('child_process');
const cluster = require('cluster');
const os = require('os');
const Redis = require('ioredis');

// Cluster configuration - use multiple workers for better performance
const NUM_WORKERS = parseInt(process.env.WORKERS) || Math.min(os.cpus().length, 4);

// Configuration via environment variables
const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN || 'sanasol.ws';
const DATA_DIR = process.env.DATA_DIR || '/app/data';
const ASSETS_PATH = process.env.ASSETS_PATH || '/app/assets/Assets.zip';
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';

// Admin token TTL in seconds (24 hours)
const ADMIN_TOKEN_TTL = 86400;

// Redis client with connection handling
const redis = new Redis(REDIS_URL, {
  retryDelayOnFailover: 100,
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});


let redisConnected = false;

redis.on('connect', () => {
  console.log('Connected to Redis/Kvrocks');
  redisConnected = true;
});

redis.on('error', (err) => {
  console.error('Redis connection error:', err.message);
  redisConnected = false;
});

redis.on('close', () => {
  console.log('Redis connection closed');
  redisConnected = false;
});

// Redis key prefixes
const REDIS_KEYS = {
  SESSION: 'session:',      // session:{token} -> session data
  AUTH_GRANT: 'authgrant:', // authgrant:{grant} -> auth grant data
  USER: 'user:',            // user:{uuid} -> user profile data
  SERVER_PLAYERS: 'server:', // server:{audience} -> SET of player UUIDs
  PLAYER_SERVER: 'player:', // player:{uuid} -> current server audience
  USERNAME: 'username:',    // username:{uuid} -> username string
  SERVER_NAME: 'servername:', // servername:{audience} -> server display name
  ADMIN_TOKEN: 'admintoken:', // admintoken:{token} -> "1" (just existence check)
};

// Session TTL in seconds (10 hours)
const SESSION_TTL = 36000;

// File path for persisted user data (fallback for migration)
const USER_DATA_FILE = path.join(DATA_DIR, 'user_data.json');

// Cache for cosmetics loaded from Assets.zip
let cachedCosmetics = null;

// Cache for full cosmetic configs (with model paths)
let cachedCosmeticConfigs = null;

// Cache for gradient sets
let cachedGradientSets = null;

// Cache for eye colors
let cachedEyeColors = null;

// Ed25519 key pair for JWT signing - persisted to survive restarts
const KEY_ID = '2025-10-01-sanasol';
const KEY_FILE = path.join(DATA_DIR, 'jwt_keys.json');

let privateKey, publicKey, publicKeyJwk;

function loadOrGenerateKeys() {
  try {
    // Try to load existing keys
    if (fs.existsSync(KEY_FILE)) {
      const keyData = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
      privateKey = crypto.createPrivateKey({
        key: Buffer.from(keyData.privateKey, 'base64'),
        format: 'der',
        type: 'pkcs8'
      });
      publicKey = crypto.createPublicKey({
        key: Buffer.from(keyData.publicKey, 'base64'),
        format: 'der',
        type: 'spki'
      });
      publicKeyJwk = publicKey.export({ format: 'jwk' });
      console.log('Loaded existing Ed25519 key pair from disk');
      return;
    }
  } catch (e) {
    console.log('Could not load existing keys:', e.message);
  }

  // Generate new keys
  const keyPair = crypto.generateKeyPairSync('ed25519');
  privateKey = keyPair.privateKey;
  publicKey = keyPair.publicKey;
  publicKeyJwk = publicKey.export({ format: 'jwk' });

  // Save keys to disk
  try {
    const dir = path.dirname(KEY_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const keyData = {
      privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      publicKey: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      createdAt: new Date().toISOString()
    };
    fs.writeFileSync(KEY_FILE, JSON.stringify(keyData, null, 2));
    console.log('Generated and saved new Ed25519 key pair');
  } catch (e) {
    console.log('Could not save keys:', e.message);
    console.log('Generated Ed25519 key pair (not persisted)');
  }
}

loadOrGenerateKeys();

// Local cache for usernames (reduces Redis roundtrips for frequent lookups)
const uuidUsernameCache = new Map();

// ============================================================================
// REDIS STORAGE LAYER - All persistence handled via Redis/Kvrocks
// ============================================================================

// Initialize Redis connection and migrate old data if needed
async function initializeRedis() {
  try {
    await redis.connect();
    console.log('Redis client connected');

    // Migrate old file-based data to Redis if it exists
    await migrateFileDataToRedis();

    // Rebuild server mappings from existing sessions
    // Disabled - only needed once after migration or after data loss
    // await rebuildServerMappings();
  } catch (e) {
    console.error('Failed to connect to Redis:', e.message);
    console.log('Server will continue but data will not persist!');
  }
}

// Rebuild server:* keys from existing sessions on startup
// This ensures server player counts are accurate after restart
async function rebuildServerMappings() {
  if (!redisConnected) return;

  try {
    console.log('Rebuilding server mappings from sessions...');

    // Clear all existing server:* keys (they may be stale)
    const oldServerKeys = await redis.keys(`${REDIS_KEYS.SERVER_PLAYERS}*`);
    if (oldServerKeys.length > 0) {
      for (const key of oldServerKeys) {
        await redis.del(key);
      }
      console.log(`Cleared ${oldServerKeys.length} stale server keys`);
    }

    // Rebuild from valid sessions
    const sessionKeys = await redis.keys(`${REDIS_KEYS.SESSION}*`);
    let rebuiltCount = 0;
    const serverCounts = new Map();

    for (const key of sessionKeys) {
      const sessionJson = await redis.get(key);
      if (!sessionJson) continue;

      try {
        const session = JSON.parse(sessionJson);
        if (session.serverAudience && session.uuid) {
          await redis.sadd(`${REDIS_KEYS.SERVER_PLAYERS}${session.serverAudience}`, session.uuid);

          // Get remaining TTL from session and apply to player mapping
          const ttl = await redis.ttl(key);
          if (ttl > 0) {
            await redis.setex(`${REDIS_KEYS.PLAYER_SERVER}${session.uuid}`, ttl, session.serverAudience);
          }

          rebuiltCount++;
          serverCounts.set(session.serverAudience, (serverCounts.get(session.serverAudience) || 0) + 1);
        }
      } catch (e) {
        // Skip invalid session
      }
    }

    console.log(`Rebuilt ${rebuiltCount} player-server mappings across ${serverCounts.size} servers`);
  } catch (e) {
    console.error('Failed to rebuild server mappings:', e.message);
  }
}

// Migrate old file-based data to Redis (one-time migration)
async function migrateFileDataToRedis() {
  if (!redisConnected) return;

  // Check if migration already done
  const migrated = await redis.get('migration:completed');
  if (migrated) return;

  console.log('Checking for data to migrate to Redis...');

  // Migrate user data
  if (fs.existsSync(USER_DATA_FILE)) {
    try {
      const fileData = JSON.parse(fs.readFileSync(USER_DATA_FILE, 'utf8'));
      let count = 0;
      for (const [uuid, data] of Object.entries(fileData)) {
        await redis.set(`${REDIS_KEYS.USER}${uuid}`, JSON.stringify(data));
        if (data.username) {
          await redis.set(`${REDIS_KEYS.USERNAME}${uuid}`, data.username);
        }
        count++;
      }
      console.log(`Migrated ${count} user records to Redis`);
    } catch (e) {
      console.log('Could not migrate user data:', e.message);
    }
  }

  // Migrate sessions file
  const sessionsFile = path.join(DATA_DIR, 'active_sessions.json');
  if (fs.existsSync(sessionsFile)) {
    try {
      const fileData = JSON.parse(fs.readFileSync(sessionsFile, 'utf8'));
      const now = Date.now();
      let sessionCount = 0;
      let grantCount = 0;

      if (fileData.sessions) {
        for (const [token, session] of Object.entries(fileData.sessions)) {
          const expiresAt = new Date(session.expiresAt).getTime();
          const ttl = Math.max(1, Math.floor((expiresAt - now) / 1000));
          if (ttl > 0) {
            await redis.setex(`${REDIS_KEYS.SESSION}${token}`, ttl, JSON.stringify(session));
            if (session.serverAudience && session.uuid) {
              await redis.sadd(`${REDIS_KEYS.SERVER_PLAYERS}${session.serverAudience}`, session.uuid);
              await redis.setex(`${REDIS_KEYS.PLAYER_SERVER}${session.uuid}`, ttl, session.serverAudience);
            }
            sessionCount++;
          }
        }
      }

      if (fileData.authGrants) {
        for (const [grant, info] of Object.entries(fileData.authGrants)) {
          const expiresAt = new Date(info.expiresAt).getTime();
          const ttl = Math.max(1, Math.floor((expiresAt - now) / 1000));
          if (ttl > 0) {
            await redis.setex(`${REDIS_KEYS.AUTH_GRANT}${grant}`, ttl, JSON.stringify(info));
            grantCount++;
          }
        }
      }

      console.log(`Migrated ${sessionCount} sessions and ${grantCount} auth grants to Redis`);
    } catch (e) {
      console.log('Could not migrate sessions:', e.message);
    }
  }

  await redis.set('migration:completed', new Date().toISOString());
  console.log('Redis migration completed');
}

// Register a new game session
async function registerSession(sessionToken, uuid, username, serverAudience = null) {
  const sessionData = {
    uuid,
    username,
    serverAudience,
    createdAt: new Date().toISOString()
  };

  if (redisConnected) {
    try {
      // Store session with TTL
      await redis.setex(`${REDIS_KEYS.SESSION}${sessionToken}`, SESSION_TTL, JSON.stringify(sessionData));

      // Track player-server association if we know the server
      if (serverAudience) {
        // Remove player from previous server if they were on a different one
        const previousServer = await redis.get(`${REDIS_KEYS.PLAYER_SERVER}${uuid}`);
        if (previousServer && previousServer !== serverAudience) {
          await redis.srem(`${REDIS_KEYS.SERVER_PLAYERS}${previousServer}`, uuid);
          console.log(`Player ${uuid} moved from server ${previousServer} to ${serverAudience}`);
        }

        await redis.sadd(`${REDIS_KEYS.SERVER_PLAYERS}${serverAudience}`, uuid);
        await redis.setex(`${REDIS_KEYS.PLAYER_SERVER}${uuid}`, SESSION_TTL, serverAudience);
      }

      // Update username cache
      if (username && username !== 'Player') {
        await redis.set(`${REDIS_KEYS.USERNAME}${uuid}`, username);
        uuidUsernameCache.set(uuid, username);
      }

      console.log(`Session registered: ${uuid} (${username}) on server ${serverAudience || 'unknown'}`);
    } catch (e) {
      console.error('Failed to register session in Redis:', e.message);
    }
  }
}

// Register an auth grant (player joining a server)
async function registerAuthGrant(authGrant, playerUuid, playerName, serverAudience) {
  const grantData = {
    playerUuid,
    playerName,
    serverAudience,
    createdAt: new Date().toISOString()
  };

  if (redisConnected) {
    try {
      // Store auth grant with TTL
      await redis.setex(`${REDIS_KEYS.AUTH_GRANT}${authGrant}`, SESSION_TTL, JSON.stringify(grantData));

      // Remove player from previous server if they were on a different one
      const previousServer = await redis.get(`${REDIS_KEYS.PLAYER_SERVER}${playerUuid}`);
      if (previousServer && previousServer !== serverAudience) {
        await redis.srem(`${REDIS_KEYS.SERVER_PLAYERS}${previousServer}`, playerUuid);
        console.log(`Player ${playerUuid} moved from server ${previousServer} to ${serverAudience}`);
      }

      // Track player-server association
      await redis.sadd(`${REDIS_KEYS.SERVER_PLAYERS}${serverAudience}`, playerUuid);
      await redis.setex(`${REDIS_KEYS.PLAYER_SERVER}${playerUuid}`, SESSION_TTL, serverAudience);

      // Update username
      await persistUsername(playerUuid, playerName);

      console.log(`Auth grant registered: ${playerUuid} (${playerName}) -> server ${serverAudience}`);
    } catch (e) {
      console.error('Failed to register auth grant in Redis:', e.message);
    }
  }
}

// Remove a session (player disconnected or session expired)
async function removeSession(sessionToken) {
  if (!redisConnected) return false;

  try {
    const sessionJson = await redis.get(`${REDIS_KEYS.SESSION}${sessionToken}`);
    if (!sessionJson) return false;

    const session = JSON.parse(sessionJson);

    // Remove from server-player mapping
    if (session.serverAudience) {
      await redis.srem(`${REDIS_KEYS.SERVER_PLAYERS}${session.serverAudience}`, session.uuid);

      // Check if server is now empty
      const remaining = await redis.scard(`${REDIS_KEYS.SERVER_PLAYERS}${session.serverAudience}`);
      if (remaining === 0) {
        await redis.del(`${REDIS_KEYS.SERVER_PLAYERS}${session.serverAudience}`);
      }
    }

    // Remove player-server mapping
    await redis.del(`${REDIS_KEYS.PLAYER_SERVER}${session.uuid}`);

    // Remove session
    await redis.del(`${REDIS_KEYS.SESSION}${sessionToken}`);

    console.log(`Session removed: ${session.uuid} (${session.username})`);
    return true;
  } catch (e) {
    console.error('Failed to remove session:', e.message);
    return false;
  }
}

// Get players on a specific server
async function getPlayersOnServer(serverAudience) {
  if (!redisConnected) return [];

  try {
    const playerUuids = await redis.smembers(`${REDIS_KEYS.SERVER_PLAYERS}${serverAudience}`);
    if (!playerUuids || playerUuids.length === 0) return [];

    const players = [];
    for (const uuid of playerUuids) {
      let username = uuidUsernameCache.get(uuid);
      if (!username) {
        username = await redis.get(`${REDIS_KEYS.USERNAME}${uuid}`);
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

// Find player by username on a specific server
async function findPlayerOnServer(serverAudience, username) {
  const players = await getPlayersOnServer(serverAudience);
  return players.filter(p => p.username.toLowerCase() === username.toLowerCase());
}

// Extract server audience from bearer token in headers
function extractServerAudienceFromHeaders(headers) {
  if (!headers || !headers.authorization) return null;

  try {
    const token = headers.authorization.replace('Bearer ', '');
    const parts = token.split('.');
    if (parts.length >= 2) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      if (payload.aud) {
        return payload.aud;
      }
      if (payload.scope === 'hytale:server' && payload.sub) {
        return payload.sub;
      }
    }
  } catch (e) {
    // Silent fail - token parsing is optional
  }
  return null;
}

// Get all active sessions (for admin API)
async function getAllActiveSessions() {
  if (!redisConnected) return { sessions: [], servers: [] };

  try {
    // Get all session keys
    const sessionKeys = await redis.keys(`${REDIS_KEYS.SESSION}*`);
    const sessions = [];
    const playerTtls = new Map(); // uuid -> ttl in seconds

    for (const key of sessionKeys) {
      const sessionJson = await redis.get(key);
      if (sessionJson) {
        const session = JSON.parse(sessionJson);
        session.token = key.replace(REDIS_KEYS.SESSION, '').substring(0, 8) + '...';

        // Get TTL for this session
        const ttl = await redis.ttl(key);
        session.ttl = ttl;
        session.ttlMinutes = Math.round(ttl / 60);
        session.ttlHours = Math.round(ttl / 3600 * 10) / 10;

        // Track highest TTL per player (in case of multiple sessions)
        if (!playerTtls.has(session.uuid) || ttl > playerTtls.get(session.uuid)) {
          playerTtls.set(session.uuid, ttl);
        }

        sessions.push(session);
      }
    }

    // Build a set of UUIDs that have valid sessions
    const validPlayerUuids = new Set(sessions.map(s => s.uuid));

    // Get all server keys with player details
    const serverKeys = await redis.keys(`${REDIS_KEYS.SERVER_PLAYERS}*`);
    const servers = [];

    for (const key of serverKeys) {
      const serverAudience = key.replace(REDIS_KEYS.SERVER_PLAYERS, '');
      const playerUuids = await redis.smembers(key);

      // Filter to only players with valid sessions
      const activePlayers = [];
      const staleUuids = [];

      for (const uuid of playerUuids) {
        if (validPlayerUuids.has(uuid)) {
          // Player has valid session
          let username = uuidUsernameCache.get(uuid);
          if (!username) {
            username = await redis.get(`${REDIS_KEYS.USERNAME}${uuid}`);
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
          // Stale UUID - no valid session
          staleUuids.push(uuid);
        }
      }

      // Clean up stale UUIDs from server set
      if (staleUuids.length > 0) {
        for (const uuid of staleUuids) {
          await redis.srem(key, uuid);
        }
        console.log(`Cleaned ${staleUuids.length} stale players from server ${serverAudience}`);
      }

      // If server has no active players, delete the server key entirely
      if (activePlayers.length === 0) {
        await redis.del(key);
        console.log(`Removed empty server: ${serverAudience}`);
        continue; // Don't add to servers list
      }

      // Get server display name
      let serverName = await getServerName(serverAudience);

      servers.push({
        audience: serverAudience,
        name: serverName,
        playerCount: activePlayers.length,
        players: activePlayers
      });
    }

    // Sort servers by player count (descending)
    servers.sort((a, b) => b.playerCount - a.playerCount);

    return { sessions, servers };
  } catch (e) {
    console.error('Failed to get active sessions:', e.message);
    return { sessions: [], servers: [] };
  }
}

// Get server display name from Redis
async function getServerName(audience) {
  if (!audience || !redisConnected) return null;

  try {
    return await redis.get(`${REDIS_KEYS.SERVER_NAME}${audience}`);
  } catch (e) {
    return null;
  }
}

// Set server display name in Redis
async function setServerName(audience, name) {
  if (!audience || !name || !redisConnected) return false;

  try {
    await redis.set(`${REDIS_KEYS.SERVER_NAME}${audience}`, name);
    console.log(`Server name set: ${audience} -> "${name}"`);
    return true;
  } catch (e) {
    console.error('Failed to set server name:', e.message);
    return false;
  }
}

// Persist username to Redis
async function persistUsername(uuid, name) {
  if (!uuid || !name || name === 'Player') return;

  // Update local cache
  uuidUsernameCache.set(uuid, name);

  if (redisConnected) {
    try {
      await redis.set(`${REDIS_KEYS.USERNAME}${uuid}`, name);

      // Also update user data
      const userKey = `${REDIS_KEYS.USER}${uuid}`;
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

// Get user data from Redis
async function getUserData(uuid) {
  if (!redisConnected) return {};

  try {
    const data = await redis.get(`${REDIS_KEYS.USER}${uuid}`);
    return data ? JSON.parse(data) : {};
  } catch (e) {
    console.error('Failed to get user data:', e.message);
    return {};
  }
}

// Save user data to Redis
async function saveUserData(uuid, data) {
  if (!redisConnected) return;

  try {
    await redis.set(`${REDIS_KEYS.USER}${uuid}`, JSON.stringify(data));
    if (data.username) {
      await redis.set(`${REDIS_KEYS.USERNAME}${uuid}`, data.username);
      uuidUsernameCache.set(uuid, data.username);
    }
  } catch (e) {
    console.error('Failed to save user data:', e.message);
  }
}

// Get username from cache or Redis
async function getUsername(uuid) {
  // Check local cache first
  if (uuidUsernameCache.has(uuid)) {
    return uuidUsernameCache.get(uuid);
  }

  if (redisConnected) {
    try {
      const username = await redis.get(`${REDIS_KEYS.USERNAME}${uuid}`);
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

// ============================================================================

// Load cosmetics from Assets.zip
function loadCosmeticsFromAssets() {
  if (cachedCosmetics) {
    return cachedCosmetics;
  }

  if (!fs.existsSync(ASSETS_PATH)) {
    console.log('Assets.zip not found at:', ASSETS_PATH);
    return null;
  }

  console.log('Loading cosmetics from:', ASSETS_PATH);

  // Map of JSON file names to cosmetic category names
  const categoryMap = {
    'BodyCharacteristics.json': 'bodyCharacteristic',
    'Capes.json': 'cape',
    'EarAccessory.json': 'earAccessory',
    'Ears.json': 'ears',
    'Eyebrows.json': 'eyebrows',
    'Eyes.json': 'eyes',
    'Faces.json': 'face',
    'FaceAccessory.json': 'faceAccessory',
    'FacialHair.json': 'facialHair',
    'Gloves.json': 'gloves',
    'Haircuts.json': 'haircut',
    'HeadAccessory.json': 'headAccessory',
    'Mouths.json': 'mouth',
    'Overpants.json': 'overpants',
    'Overtops.json': 'overtop',
    'Pants.json': 'pants',
    'Shoes.json': 'shoes',
    'SkinFeatures.json': 'skinFeature',
    'Undertops.json': 'undertop',
    'Underwear.json': 'underwear',
  };

  const cosmetics = {};

  for (const [fileName, categoryName] of Object.entries(categoryMap)) {
    const entryPath = `Cosmetics/CharacterCreator/${fileName}`;

    try {
      // Use unzip -p to extract file content to stdout
      const content = execSync(`unzip -p "${ASSETS_PATH}" "${entryPath}"`, {
        encoding: 'utf8',
        maxBuffer: 10 * 1024 * 1024
      });

      const items = JSON.parse(content);
      const ids = items
          .filter(item => item && item.Id)
          .map(item => item.Id);

      if (ids.length > 0) {
        cosmetics[categoryName] = ids;
        console.log(`  Loaded ${ids.length} ${categoryName} items`);
      }
    } catch (e) {
      // File might not exist or parse error - silently skip
    }
  }

  if (Object.keys(cosmetics).length > 0) {
    cachedCosmetics = cosmetics;
    console.log('Cosmetics loaded successfully from Assets.zip');
    return cosmetics;
  }

  console.log('No cosmetics loaded from Assets.zip');
  return null;
}

// Load full cosmetic configs with model paths for avatar rendering
function loadCosmeticConfigs() {
  if (cachedCosmeticConfigs) {
    return cachedCosmeticConfigs;
  }

  if (!fs.existsSync(ASSETS_PATH)) {
    return null;
  }

  const categoryFiles = {
    'Haircuts.json': 'haircut',
    'Pants.json': 'pants',
    'Overtops.json': 'overtop',
    'Undertops.json': 'undertop',
    'Shoes.json': 'shoes',
    'HeadAccessory.json': 'headAccessory',
    'FaceAccessory.json': 'faceAccessory',
    'EarAccessory.json': 'earAccessory',
    'Eyebrows.json': 'eyebrows',
    'Eyes.json': 'eyes',
    'Faces.json': 'face',
    'FacialHair.json': 'facialHair',
    'Gloves.json': 'gloves',
    'Capes.json': 'cape',
    'Overpants.json': 'overpants',
    'Mouths.json': 'mouth',
    'Ears.json': 'ears',
    'Underwear.json': 'underwear',
    'BodyCharacteristics.json': 'bodyCharacteristic',
  };

  const configs = {};

  for (const [fileName, category] of Object.entries(categoryFiles)) {
    try {
      const content = execSync(`unzip -p "${ASSETS_PATH}" "Cosmetics/CharacterCreator/${fileName}"`, {
        encoding: 'utf8',
        maxBuffer: 10 * 1024 * 1024
      });
      const items = JSON.parse(content);
      configs[category] = {};
      for (const item of items) {
        if (item && item.Id) {
          configs[category][item.Id] = item;
        }
      }
    } catch (e) {
      // Skip if file doesn't exist
    }
  }

  cachedCosmeticConfigs = configs;
  return configs;
}

// Load gradient sets for color tinting
function loadGradientSets() {
  if (cachedGradientSets) {
    return cachedGradientSets;
  }

  if (!fs.existsSync(ASSETS_PATH)) {
    return null;
  }

  try {
    const content = execSync(`unzip -p "${ASSETS_PATH}" "Cosmetics/CharacterCreator/GradientSets.json"`, {
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024
    });
    cachedGradientSets = JSON.parse(content);
    return cachedGradientSets;
  } catch (e) {
    return null;
  }
}

// Load eye colors
function loadEyeColors() {
  if (cachedEyeColors) {
    return cachedEyeColors;
  }

  if (!fs.existsSync(ASSETS_PATH)) {
    return null;
  }

  try {
    const content = execSync(`unzip -p "${ASSETS_PATH}" "Cosmetics/CharacterCreator/EyeColors.json"`, {
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024
    });
    const colors = JSON.parse(content);
    // Convert to map for easy lookup
    cachedEyeColors = {};
    for (const color of colors) {
      if (color.Id) {
        cachedEyeColors[color.Id] = color;
      }
    }
    return cachedEyeColors;
  } catch (e) {
    return null;
  }
}

// Extract asset from Assets.zip
function extractAsset(assetPath) {
  if (!fs.existsSync(ASSETS_PATH)) {
    return null;
  }

  // Normalize path - try Common/ prefix if not found
  const pathsToTry = [
    assetPath,
    `Common/${assetPath}`,
    assetPath.replace(/^Common\//, '')
  ];

  for (const tryPath of pathsToTry) {
    try {
      const content = execSync(`unzip -p "${ASSETS_PATH}" "${tryPath}"`, {
        maxBuffer: 50 * 1024 * 1024
      });
      return content;
    } catch (e) {
      // Try next path
    }
  }

  return null;
}

// Resolve skin part to model/texture paths
function resolveSkinPart(category, partValue, configs, gradientSets) {
  if (!partValue || !configs || !configs[category]) {
    return null;
  }

  // Parse "PartId.ColorId" or "PartId.ColorId.Variant" format
  const parts = partValue.split('.');
  const partId = parts[0];
  const colorId = parts.length > 1 ? parts[1] : null;
  const variantId = parts.length > 2 ? parts[2] : null;

  const partConfig = configs[category][partId];
  if (!partConfig) {
    return null;
  }

  const result = {
    id: partId,
    colorId: colorId,
    name: partConfig.Name
  };

  // Handle items with Variants (like capes)
  if (partConfig.Variants) {
    const variant = variantId ? partConfig.Variants[variantId] : partConfig.Variants['Neck_Piece'] || Object.values(partConfig.Variants)[0];
    if (variant) {
      result.model = variant.Model;
      result.greyscaleTexture = variant.GreyscaleTexture;

      // Handle variant-specific textures
      if (variant.Textures && colorId && variant.Textures[colorId]) {
        result.texture = variant.Textures[colorId].Texture;
        result.baseColor = variant.Textures[colorId].BaseColor;
      } else if (variant.GreyscaleTexture && partConfig.GradientSet) {
        result.gradientSet = partConfig.GradientSet;
        // Resolve gradient color
        if (colorId && gradientSets) {
          const gradientSetConfig = gradientSets.find(g => g.Id === partConfig.GradientSet);
          if (gradientSetConfig && gradientSetConfig.Gradients && gradientSetConfig.Gradients[colorId]) {
            result.gradientTexture = gradientSetConfig.Gradients[colorId].Texture;
            result.baseColor = gradientSetConfig.Gradients[colorId].BaseColor;
          }
        }
      }
    }
    return result;
  }

  // Standard item without variants
  result.model = partConfig.Model;

  // Handle textures - either specific color texture or greyscale + gradient
  if (partConfig.Textures && colorId && partConfig.Textures[colorId]) {
    result.texture = partConfig.Textures[colorId].Texture;
    result.baseColor = partConfig.Textures[colorId].BaseColor;
  } else if (partConfig.GreyscaleTexture) {
    result.greyscaleTexture = partConfig.GreyscaleTexture;
    result.gradientSet = partConfig.GradientSet;

    // Resolve gradient color
    if (colorId && partConfig.GradientSet && gradientSets) {
      const gradientSetConfig = gradientSets.find(g => g.Id === partConfig.GradientSet);
      if (gradientSetConfig && gradientSetConfig.Gradients && gradientSetConfig.Gradients[colorId]) {
        result.gradientTexture = gradientSetConfig.Gradients[colorId].Texture;
        result.baseColor = gradientSetConfig.Gradients[colorId].BaseColor;
      }
    }
  }

  return result;
}

// Generate a JWT token with proper Ed25519 signing
function generateToken(payload) {
  const header = Buffer.from(JSON.stringify({
    alg: 'EdDSA',
    kid: KEY_ID,
    typ: 'JWT'
  })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${header}.${body}`;

  // Sign with Ed25519 private key
  const signature = crypto.sign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

// Generate identity token for the game client/server
function generateIdentityToken(uuid, name, entitlements = ['game.base']) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 36000; // 10 hours

  return generateToken({
    sub: uuid,
    name: name,
    username: name,
    entitlements: entitlements,
    scope: 'hytale:server hytale:client',
    iat: now,
    exp: exp,
    iss: `https://sessions.${DOMAIN}`,
    jti: crypto.randomUUID()
  });
}

// Generate session token for the game server
function generateSessionToken(uuid) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 36000; // 10 hours

  return generateToken({
    sub: uuid,
    scope: 'hytale:server',
    iat: now,
    exp: exp,
    iss: `https://sessions.${DOMAIN}`,
    jti: crypto.randomUUID()
  });
}

async function handleRequest(req, res) {
  const timestamp = new Date().toISOString();
  // Skip logging for telemetry endpoints (too noisy)
  if (!req.url.includes('/telemetry')) {
    console.log(`${timestamp} ${req.method} ${req.url}`);
  }

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Parse URL
  const url = new URL(req.url, `http://${req.headers.host}`);

  // Handle binary uploads (like head-cache) before consuming body as string
  const headCacheMatch = url.pathname.match(/^\/avatar\/([^/]+)\/head-cache$/);
  if (headCacheMatch && req.method === 'POST') {
    handleHeadImageCache(req, res, headCacheMatch[1], url);
    return;
  }

  // Collect body for POST requests
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    try {
      const jsonBody = body ? JSON.parse(body) : {};
      routeRequest(req, res, url, jsonBody, req.headers);
    } catch (e) {
      routeRequest(req, res, url, {}, req.headers);
    }
  });
}

async function routeRequest(req, res, url, body, headers) {
  const urlPath = url.pathname;

  // Extract UUID and name from body first
  let uuid = body.uuid || crypto.randomUUID();
  let name = body.name || null;
  let tokenScope = null;

  // If we have a valid name from body (not 'Player'), cache it immediately
  if (uuid && name && name !== 'Player') {
    uuidUsernameCache.set(uuid, name);
    console.log(`Cached username from body for UUID ${uuid}: ${name}`);
  }

  // Extract UUID and name from Authorization header
  if (headers && headers.authorization) {
    try {
      const token = headers.authorization.replace('Bearer ', '');
      const parts = token.split('.');
      if (parts.length >= 2) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (payload.sub) uuid = payload.sub;
        if (payload.scope) tokenScope = payload.scope;

        // Extract name from token
        let tokenName = null;
        if (payload.username) tokenName = payload.username;
        else if (payload.name) tokenName = payload.name;

        // Cache token name if it's valid and from a player token
        if (uuid && tokenName && tokenName !== 'Player' && tokenScope &&
            (tokenScope.includes('hytale:client') || tokenScope.includes('hytale:editor'))) {
          uuidUsernameCache.set(uuid, tokenName);
          console.log(`Cached username from token for UUID ${uuid}: ${tokenName}`);
          name = tokenName;
          // Persist to storage
          persistUsername(uuid, tokenName);
        }
      }
    } catch (e) {}
  }

  // If we don't have a valid name yet, try the cache
  if (!name || name === 'Player') {
    const cachedName = uuidUsernameCache.get(uuid);
    if (cachedName) {
      name = cachedName;
      console.log(`Using cached username for UUID ${uuid}: ${name}`);
    }
  }

  // Final fallback
  if (!name) name = 'Player';

  // Persist valid username from body (e.g., from /game-session/new)
  if (uuid && name && name !== 'Player') {
    persistUsername(uuid, name);
  }

  // Avatar viewer routes
  if (urlPath.startsWith('/avatar/')) {
    handleAvatarRoutes(req, res, urlPath, body);
    return;
  }

  // Customizer route
  if (urlPath.startsWith('/customizer')) {
    handleCustomizerRoute(req, res, urlPath);
    return;
  }

  // Cosmetics list API
  if (urlPath === '/cosmetics/list') {
    handleCosmeticsList(req, res);
    return;
  }

  // Single cosmetic item data API (for 3D thumbnail rendering)
  if (urlPath.startsWith('/cosmetics/item/')) {
    handleCosmeticItem(req, res, urlPath);
    return;
  }

  // Static assets route
  if (urlPath.startsWith('/assets/')) {
    handleStaticAssets(req, res, urlPath);
    return;
  }

  // Asset extraction route
  if (urlPath.startsWith('/asset/')) {
    handleAssetRoute(req, res, urlPath);
    return;
  }

  // Health check
  if (urlPath === '/health' || urlPath === '/') {
    sendJson(res, 200, { status: 'ok', server: 'hytale-auth', domain: DOMAIN });
    return;
  }

  // Ignore favicon requests
  if (urlPath === '/favicon.ico') {
    res.writeHead(204);
    res.end();
    return;
  }

  // JWKS endpoint for JWT signature verification
  if (urlPath === '/.well-known/jwks.json' || urlPath === '/jwks.json') {
    sendJson(res, 200, {
      keys: [{
        kty: publicKeyJwk.kty,
        crv: publicKeyJwk.crv,
        x: publicKeyJwk.x,
        kid: KEY_ID,
        use: 'sig',
        alg: 'EdDSA'
      }]
    });
    return;
  }

  // Game session endpoints
  if (urlPath === '/game-session/new') {
    handleGameSessionNew(req, res, body, uuid, name);
    return;
  }

  if (urlPath === '/game-session/refresh') {
    await handleGameSessionRefresh(req, res, body, uuid, name, headers);
    return;
  }

  if (urlPath === '/game-session/child' || urlPath.includes('/game-session/child')) {
    handleGameSessionChild(req, res, body, uuid, name);
    return;
  }

  // Authorization grant endpoint - server requests this to authorize a client connection
  if (urlPath === '/game-session/authorize' || urlPath.includes('/authorize') || urlPath.includes('/auth-grant')) {
    handleAuthorizationGrant(req, res, body, uuid, name, headers);
    return;
  }

  // Token exchange endpoint - client exchanges auth grant for access token
  if (urlPath === '/server-join/auth-token' || urlPath === '/game-session/exchange' || urlPath.includes('/auth-token')) {
    handleTokenExchange(req, res, body, uuid, name, headers);
    return;
  }

  // Session/Auth endpoints
  if (urlPath.includes('/session') || urlPath.includes('/child')) {
    handleSession(req, res, body, uuid, name);
    return;
  }

  if (urlPath.includes('/auth')) {
    handleAuth(req, res, body, uuid, name);
    return;
  }

  if (urlPath.includes('/token')) {
    handleToken(req, res, body, uuid, name);
    return;
  }

  if (urlPath.includes('/validate') || urlPath.includes('/verify')) {
    handleValidate(req, res, body, uuid, name);
    return;
  }

  if (urlPath.includes('/refresh')) {
    handleRefresh(req, res, body, uuid, name);
    return;
  }

  // Account data endpoints
  if (urlPath === '/my-account/game-profile' || urlPath.includes('/game-profile')) {
    handleGameProfile(req, res, body, uuid, name);
    return;
  }

  if (urlPath === '/my-account/skin') {
    handleSkin(req, res, body, uuid, name);
    return;
  }

  if (urlPath === '/my-account/cosmetics' || urlPath.includes('/my-account/cosmetics')) {
    handleCosmetics(req, res, body, uuid, name);
    return;
  }

  if (urlPath === '/my-account/get-launcher-data') {
    handleLauncherData(req, res, body, uuid, name);
    return;
  }

  if (urlPath === '/my-account/get-profiles') {
    handleGetProfiles(req, res, body, uuid, name);
    return;
  }

  // Bug reports and feedback
  if (urlPath === '/bugs/create' || urlPath === '/feedback/create') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Game session delete (logout/cleanup)
  if (urlPath === '/game-session' && req.method === 'DELETE') {
    handleGameSessionDelete(req, res, headers);
    return;
  }

  // Admin login endpoint (no auth required)
  if (urlPath === '/admin/login' && req.method === 'POST') {
    await handleAdminLogin(req, res, body);
    return;
  }

  // Admin verify endpoint (check if token is valid)
  if (urlPath === '/admin/verify') {
    const token = headers['x-admin-token'] || url.searchParams.get('token');
    if (token && redisConnected) {
      try {
        const exists = await redis.exists(REDIS_KEYS.ADMIN_TOKEN + token);
        if (exists) {
          // Refresh TTL on valid token
          await redis.expire(REDIS_KEYS.ADMIN_TOKEN + token, ADMIN_TOKEN_TTL);
          sendJson(res, 200, { valid: true });
          return;
        }
      } catch (e) {
        console.error('Redis error checking admin token:', e.message);
      }
    }
    sendJson(res, 401, { valid: false });
    return;
  }

  // Admin dashboard HTML page (no auth - login happens client-side)
  if (urlPath === '/admin' || urlPath === '/admin/') {
    handleAdminDashboard(req, res);
    return;
  }

  // Test page for head embed
  if (urlPath === '/test/head') {
    handleTestHeadPage(req, res);
    return;
  }

  // Protected admin API routes - require token
  if (urlPath.startsWith('/admin/')) {
    const token = headers['x-admin-token'];
    let validToken = false;
    if (token && redisConnected) {
      try {
        validToken = await redis.exists(REDIS_KEYS.ADMIN_TOKEN + token);
      } catch (e) {
        console.error('Redis error checking admin token:', e.message);
      }
    }
    if (!validToken) {
      sendJson(res, 401, { error: 'Unauthorized. Please login at /admin' });
      return;
    }
  }

  // Active sessions API - list all servers and players
  if (urlPath === '/admin/sessions' || urlPath === '/sessions/active') {
    handleActiveSessions(req, res);
    return;
  }

  // Admin stats API (lightweight summary)
  if (urlPath === '/admin/stats') {
    handleAdminStats(req, res);
    return;
  }

  // Admin servers API (paginated server list with players)
  if (urlPath.startsWith('/admin/servers')) {
    handleAdminServers(req, res, url);
    return;
  }

  // Server name registration - POST /admin/server-name
  if (urlPath === '/admin/server-name' && req.method === 'POST') {
    handleSetServerName(req, res, body);
    return;
  }

  // Get list of player UUIDs that need head pre-rendering
  if (urlPath === '/admin/prerender-queue') {
    await handlePrerenderQueue(req, res);
    return;
  }

  // Profile lookup by UUID - for ProfileServiceClient.getProfileByUuid()
  if (urlPath.startsWith('/profile/uuid/')) {
    const lookupUuid = urlPath.replace('/profile/uuid/', '');
    handleProfileLookupByUuid(req, res, lookupUuid, headers);
    return;
  }

  // Profile lookup by username - for ProfileServiceClient.getProfileByUsername()
  if (urlPath.startsWith('/profile/username/')) {
    const lookupUsername = decodeURIComponent(urlPath.replace('/profile/username/', ''));
    handleProfileLookupByUsername(req, res, lookupUsername, headers);
    return;
  }

  // Profile endpoint
  if (urlPath.includes('/profile') || urlPath.includes('/user') || urlPath.includes('/me')) {
    handleProfile(req, res, body, uuid, name);
    return;
  }

  // Cosmetics endpoint
  if (urlPath.includes('/cosmetic') || urlPath.includes('/unlocked') || urlPath.includes('/inventory')) {
    handleCosmetics(req, res, body, uuid, name);
    return;
  }

  // Telemetry endpoint
  if (urlPath.includes('/telemetry') || urlPath.includes('/analytics') || urlPath.includes('/event')) {
    sendJson(res, 200, { success: true, received: true });
    return;
  }

  // Catch-all - return comprehensive response that might satisfy various requests
  console.log(`Unknown endpoint: ${urlPath}`);
  const authGrant = generateAuthorizationGrant(uuid, name, crypto.randomUUID());
  const accessToken = generateIdentityToken(uuid, name);
  sendJson(res, 200, {
    success: true,
    identityToken: accessToken,
    sessionToken: generateSessionToken(uuid),
    authorizationGrant: authGrant,
    accessToken: accessToken,
    tokenType: 'Bearer',
    user: { uuid, name, premium: true }
  });
}

// Generate authorization grant token for server connection
function generateAuthorizationGrant(uuid, name, audience) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 36000; // 10 hours

  return generateToken({
    sub: uuid,
    name: name,
    username: name,
    aud: audience,
    scope: 'hytale:server hytale:client',
    iat: now,
    exp: exp,
    iss: `https://sessions.${DOMAIN}`,
    jti: crypto.randomUUID()
  });
}

function handleAuthorizationGrant(req, res, body, uuid, name, headers) {
  console.log('Authorization grant request:', uuid, name, 'body:', JSON.stringify(body));

  // Extract user info from identity token if present in request
  if (body.identityToken) {
    try {
      const parts = body.identityToken.split('.');
      if (parts.length >= 2) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (payload.sub) uuid = payload.sub;
        if (payload.name) name = payload.name;
        if (payload.username) name = payload.username;
        console.log('Extracted from identity token - uuid:', uuid, 'name:', name);
      }
    } catch (e) {
      console.log('Failed to parse identity token:', e.message);
    }
  }

  // Extract audience from request (server's unique ID)
  const audience = body.aud || body.audience || body.server_id || crypto.randomUUID();

  const authGrant = generateAuthorizationGrant(uuid, name, audience);
  const expiresAt = new Date(Date.now() + 36000 * 1000).toISOString();

  // Track this auth grant - player is joining this server
  registerAuthGrant(authGrant, uuid, name, audience);

  sendJson(res, 200, {
    authorizationGrant: authGrant,
    expiresAt: expiresAt
  });
}

function handleTokenExchange(req, res, body, uuid, name, headers) {
  console.log('Token exchange request:', uuid, name);

  // Extract audience from the authorization grant JWT
  let audience = null;
  if (body.authorizationGrant) {
    try {
      const parts = body.authorizationGrant.split('.');
      if (parts.length >= 2) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        audience = payload.aud;
        if (payload.sub) uuid = payload.sub;
        if (payload.name) name = payload.name;
        if (payload.username) name = payload.username; // Prefer username over name
        console.log('Extracted from auth grant - aud:', audience, 'sub:', uuid, 'name:', name);
      }
    } catch (e) {
      console.log('Failed to parse auth grant:', e.message);
    }
  }

  // Get certificate fingerprint from request (for mTLS binding)
  const certFingerprint = body.x509Fingerprint || body.certFingerprint || body.fingerprint;
  console.log('Certificate fingerprint:', certFingerprint);

  const now = Math.floor(Date.now() / 1000);
  const exp = now + 36000; // 10 hours

  // Generate access token with audience and certificate binding
  const tokenPayload = {
    sub: uuid,
    name: name,
    username: name,
    aud: audience,
    entitlements: ['game.base'],
    scope: 'hytale:server hytale:client',
    iat: now,
    exp: exp,
    iss: `https://sessions.${DOMAIN}`,
    jti: crypto.randomUUID()
  };

  // Add certificate confirmation if fingerprint provided (mTLS binding)
  if (certFingerprint) {
    tokenPayload.cnf = {
      'x5t#S256': certFingerprint
    };
  }

  const accessToken = generateToken(tokenPayload);

  const refreshToken = generateSessionToken(uuid);
  const expiresAt = new Date(Date.now() + 36000 * 1000).toISOString();

  // Register session with server audience so it persists across restarts
  registerSession(accessToken, uuid, name, audience);

  sendJson(res, 200, {
    accessToken: accessToken,
    tokenType: 'Bearer',
    expiresIn: 36000,
    refreshToken: refreshToken,
    expiresAt: expiresAt,
    scope: 'hytale:server hytale:client'
  });
}

// Create new game session (used by official launcher and servers)
function handleGameSessionNew(req, res, body, uuid, name) {
  console.log('game-session/new:', uuid, name);

  // Extract UUID from body if provided
  if (body.uuid) uuid = body.uuid;

  const identityToken = generateIdentityToken(uuid, name);
  const sessionToken = generateSessionToken(uuid);
  const expiresAt = new Date(Date.now() + 36000 * 1000).toISOString();

  // Register the session (server audience not known at this point)
  registerSession(sessionToken, uuid, name, null);

  sendJson(res, 200, {
    sessionToken: sessionToken,
    identityToken: identityToken,
    expiresAt: expiresAt
  });
}

// Refresh existing game session
async function handleGameSessionRefresh(req, res, body, uuid, name, headers) {
  console.log('game-session/refresh:', uuid, name);

  let oldSessionToken = null;

  // Extract info from existing session token if provided in body
  if (body.sessionToken) {
    oldSessionToken = body.sessionToken;
  }

  // Or from Authorization header
  if (headers && headers.authorization) {
    const token = headers.authorization.replace('Bearer ', '');
    if (token.includes('.')) {
      oldSessionToken = token;
    }
  }

  // Parse old session token
  if (oldSessionToken) {
    try {
      const parts = oldSessionToken.split('.');
      if (parts.length >= 2) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (payload.sub) uuid = payload.sub;
        if (payload.name) name = payload.name;
      }
    } catch (e) {
      console.log('Failed to parse session token:', e.message);
    }

    // Remove old session
    removeSession(oldSessionToken);
  }

  const identityToken = generateIdentityToken(uuid, name);
  const sessionToken = generateSessionToken(uuid);
  const expiresAt = new Date(Date.now() + 36000 * 1000).toISOString();

  // Get server from player mapping in Redis
  let serverAudience = null;
  if (redisConnected) {
    try {
      serverAudience = await redis.get(`${REDIS_KEYS.PLAYER_SERVER}${uuid}`);
    } catch (e) {}
  }

  // Register new session
  registerSession(sessionToken, uuid, name, serverAudience);

  sendJson(res, 200, {
    sessionToken: sessionToken,
    identityToken: identityToken,
    expiresAt: expiresAt
  });
}

function handleGameSessionChild(req, res, body, uuid, name) {
  console.log('game-session/child:', uuid, name);

  const scopes = body.scopes || ['hytale:server'];
  const scopeString = Array.isArray(scopes) ? scopes.join(' ') : scopes;

  const childIdentityToken = generateToken({
    sub: uuid,
    name: name,
    username: name,
    entitlements: ['game.base'],
    scope: scopeString,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400,
    iss: `https://sessions.${DOMAIN}`,
    jti: crypto.randomUUID()
  });

  const sessionToken = generateSessionToken(uuid);
  const expiresAt = new Date(Date.now() + 86400 * 1000).toISOString();

  sendJson(res, 200, {
    sessionToken: sessionToken,
    identityToken: childIdentityToken,
    expiresAt: expiresAt
  });
}

// Handle game session delete (player disconnect/logout)
function handleGameSessionDelete(req, res, headers) {
  console.log('game-session DELETE request');

  let sessionToken = null;

  // Get session token from Authorization header
  if (headers && headers.authorization) {
    sessionToken = headers.authorization.replace('Bearer ', '');
  }

  if (sessionToken) {
    const removed = removeSession(sessionToken);
    console.log(`Session delete: ${removed ? 'removed' : 'not found'}`);
  }

  res.writeHead(204);
  res.end();
}

// Active sessions API - returns all servers and their players
async function handleActiveSessions(req, res) {
  const { sessions, servers } = await getAllActiveSessions();

  // Count unique players
  const uniquePlayers = new Set(sessions.map(s => s.uuid));

  sendJson(res, 200, {
    servers,
    sessions: sessions.length,
    totalServers: servers.length,
    totalPlayers: uniquePlayers.size,
    timestamp: new Date().toISOString()
  });
}

// Set server name - POST /admin/server-name
async function handleSetServerName(req, res, body) {
  const { audience, name } = body;

  if (!audience) {
    sendJson(res, 400, { error: 'Missing audience (server ID)' });
    return;
  }

  if (!name) {
    sendJson(res, 400, { error: 'Missing server name' });
    return;
  }

  const success = await setServerName(audience, name);

  if (success) {
    sendJson(res, 200, { success: true, audience, name });
  } else {
    sendJson(res, 500, { error: 'Failed to set server name' });
  }
}

// Get list of player UUIDs that need head pre-rendering
// Returns UUIDs of active players whose head cache doesn't exist
async function handlePrerenderQueue(req, res) {
  const bgParam = 'black'; // Default background used in admin page

  // Count total cached files on disk
  let totalCachedFiles = 0;
  try {
    if (fs.existsSync(HEAD_CACHE_DIR)) {
      const files = fs.readdirSync(HEAD_CACHE_DIR);
      totalCachedFiles = files.filter(f => f.endsWith('.png')).length;
    }
  } catch (e) {
    // Ignore errors reading cache dir
  }

  if (!redisConnected) {
    sendJson(res, 200, { uuids: [], totalCachedFiles, error: 'Redis not connected' });
    return;
  }

  try {
    // Get all active player UUIDs from all servers
    const serverKeys = [];
    let cursor = '0';
    do {
      const [newCursor, keys] = await redis.scan(cursor, 'MATCH', `${REDIS_KEYS.SERVER_PLAYERS}*`, 'COUNT', 500);
      cursor = newCursor;
      serverKeys.push(...keys);
    } while (cursor !== '0');

    // Collect all player UUIDs
    const allUuids = new Set();
    for (const key of serverKeys) {
      const uuids = await redis.smembers(key);
      uuids.forEach(uuid => allUuids.add(uuid));
    }

    // Filter to only those without cached head images
    const uncachedUuids = [];
    for (const uuid of allUuids) {
      const cacheKey = `${uuid}_${bgParam}`;
      const cached = getHeadCacheFromDisk(cacheKey);
      if (!cached) {
        uncachedUuids.push(uuid);
      }
    }

    sendJson(res, 200, {
      uuids: uncachedUuids,
      total: allUuids.size,
      cached: allUuids.size - uncachedUuids.length,
      uncached: uncachedUuids.length,
      totalCachedFiles
    });
  } catch (e) {
    console.error('Error getting prerender queue:', e.message);
    sendJson(res, 500, { error: e.message });
  }
}

// Admin stats API - detailed statistics
// Lightweight admin stats - just counts, no player lists
async function handleAdminStats(req, res) {
  let keyCounts = { sessions: 0, authGrants: 0, users: 0, servers: 0 };
  let redisInfo = { connected: false };

  if (redisConnected) {
    try {
      // Use SCAN with COUNT for efficient counting on large datasets
      const sessionKeys = await redis.keys(`${REDIS_KEYS.SESSION}*`);
      const authGrantKeys = await redis.keys(`${REDIS_KEYS.AUTH_GRANT}*`);
      const userKeys = await redis.keys(`${REDIS_KEYS.USER}*`);
      const serverKeys = await redis.keys(`${REDIS_KEYS.SERVER_PLAYERS}*`);

      keyCounts = {
        sessions: sessionKeys.length,
        authGrants: authGrantKeys.length,
        users: userKeys.length,
        servers: serverKeys.length
      };

      // Get unique player count from sessions
      const uniquePlayers = new Set();
      for (const key of sessionKeys) {
        const sessionJson = await redis.get(key);
        if (sessionJson) {
          try {
            const session = JSON.parse(sessionJson);
            if (session.uuid) uniquePlayers.add(session.uuid);
          } catch (e) {}
        }
      }
      keyCounts.activePlayers = uniquePlayers.size;

      redisInfo = { connected: true };
    } catch (e) {
      redisInfo = { connected: true, error: e.message };
    }
  }

  sendJson(res, 200, {
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    redis: redisInfo,
    keys: keyCounts,
    activeSessions: keyCounts.sessions,
    activeServers: keyCounts.servers,
    activePlayers: keyCounts.activePlayers || 0,
    timestamp: new Date().toISOString()
  }, req);
}

// Paginated server list with players - /admin/servers?page=1&limit=10
// Optimized: sorts by player count, fetches details only for requested page
async function handleAdminServers(req, res, url) {
  const page = parseInt(url.searchParams.get('page')) || 1;
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 10, 50); // Max 50 per page
  const offset = (page - 1) * limit;

  if (!redisConnected) {
    sendJson(res, 200, {
      servers: [],
      pagination: { page, limit, totalServers: 0, totalPages: 0, hasNext: false, hasPrev: false },
      timestamp: new Date().toISOString()
    }, req);
    return;
  }

  try {
    // Step 1: Get all server keys using SCAN
    const serverKeys = [];
    let cursor = '0';
    do {
      const [newCursor, keys] = await redis.scan(cursor, 'MATCH', `${REDIS_KEYS.SERVER_PLAYERS}*`, 'COUNT', 500);
      cursor = newCursor;
      serverKeys.push(...keys);
    } while (cursor !== '0');

    // Step 2: Get player counts for all servers (SCARD is O(1), very fast)
    // Filter out 'hytale-client' which contains ALL players with valid tokens (too large to display)
    const serverCounts = (await Promise.all(serverKeys.map(async (key) => ({
      key,
      audience: key.replace(REDIS_KEYS.SERVER_PLAYERS, ''),
      count: await redis.scard(key)
    })))).filter(s => s.audience !== 'hytale-client');

    // Step 3: Sort by player count descending (most active first)
    serverCounts.sort((a, b) => b.count - a.count);

    const totalServers = serverCounts.length;
    const totalPages = Math.ceil(totalServers / limit);

    // Step 4: Get only the servers for this page
    const pageServers = serverCounts.slice(offset, offset + limit);

    // Step 5: Fetch full details only for this page's servers (in parallel)
    const servers = await Promise.all(pageServers.map(async ({ key, audience, count }) => {
      // Get player UUIDs and server name in parallel
      const [playerUuids, serverName] = await Promise.all([
        redis.smembers(key),
        redis.get(`${REDIS_KEYS.SERVER_NAME}${audience}`)
      ]);

      // Get usernames and TTLs for players (in parallel)
      const players = await Promise.all(playerUuids.map(async (uuid) => {
        // Get username and TTL in parallel
        let username = uuidUsernameCache.get(uuid);

        const [usernameFromRedis, ttl] = await Promise.all([
          username ? Promise.resolve(null) : redis.get(`${REDIS_KEYS.USERNAME}${uuid}`),
          redis.ttl(`${REDIS_KEYS.PLAYER_SERVER}${uuid}`) // player:{uuid} has TTL set
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

    sendJson(res, 200, {
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
    }, req);
  } catch (e) {
    console.error('handleAdminServers error:', e.message);
    sendJson(res, 500, { error: 'Failed to fetch servers' }, req);
  }
}

// Admin login - POST /admin/login
async function handleAdminLogin(req, res, body) {
  const { password } = body;

  if (!password) {
    sendJson(res, 400, { error: 'Password required' });
    return;
  }

  if (password !== ADMIN_PASSWORD) {
    sendJson(res, 401, { error: 'Invalid password' });
    return;
  }

  // Generate a random token
  const token = crypto.randomBytes(32).toString('hex');

  // Store in Redis with TTL (shared across all workers)
  if (redisConnected) {
    try {
      await redis.setex(REDIS_KEYS.ADMIN_TOKEN + token, ADMIN_TOKEN_TTL, '1');
    } catch (e) {
      console.error('Redis error storing admin token:', e.message);
      sendJson(res, 500, { error: 'Failed to create session' });
      return;
    }
  } else {
    sendJson(res, 503, { error: 'Redis not available' });
    return;
  }

  console.log(`Admin login successful, token: ${token.substring(0, 8)}...`);
  sendJson(res, 200, { token });
}

// Admin dashboard HTML page
function handleAdminDashboard(req, res) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Hytale Auth Server - Admin Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: #e0e0e0;
      min-height: 100vh;
      padding: 20px;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 {
      text-align: center;
      color: #00d4ff;
      margin-bottom: 30px;
      font-size: 2.5em;
      text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .stat-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    }
    .stat-value {
      font-size: 3em;
      font-weight: bold;
      color: #00d4ff;
      text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
    }
    .stat-label { color: #888; margin-top: 5px; font-size: 0.9em; }
    .section {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .section h2 {
      color: #00d4ff;
      margin-bottom: 15px;
      font-size: 1.3em;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      padding-bottom: 10px;
    }
    .server-card {
      background: rgba(0, 212, 255, 0.1);
      border: 1px solid rgba(0, 212, 255, 0.2);
      border-radius: 8px;
      padding: 15px;
      margin-bottom: 15px;
    }
    .server-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    .server-name {
      font-weight: bold;
      color: #00d4ff;
      font-size: 1.1em;
    }
    .server-audience {
      font-family: monospace;
      font-size: 0.75em;
      color: #888;
      margin-top: 2px;
      margin-bottom: 8px;
    }
    .player-count {
      background: #00d4ff;
      color: #1a1a2e;
      padding: 3px 10px;
      border-radius: 20px;
      font-weight: bold;
      font-size: 0.85em;
    }
    .players-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
    }
    .player-tag {
      background: rgba(255, 255, 255, 0.1);
      padding: 6px 12px;
      border-radius: 15px;
      font-size: 0.85em;
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 8px;
    }
    .player-tag .player-avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: rgba(0, 0, 0, 0.3);
      flex-shrink: 0;
      overflow: hidden;
      border: none;
    }
    .player-tag .player-avatar-img {
      width: 40px;
      height: 40px;
      border-radius: 50%;
    }
    .player-tag .player-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .player-tag .player-name {
      color: #fff;
      font-weight: 500;
    }
    .player-tag .uuid {
      color: #666;
      font-size: 0.7em;
      font-family: monospace;
    }
    .status-dot {
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      margin-right: 8px;
    }
    .status-dot.online { background: #00ff88; box-shadow: 0 0 10px #00ff88; }
    .status-dot.offline { background: #ff4444; }
    .ttl-badge {
      font-size: 0.7em;
      padding: 2px 6px;
      border-radius: 10px;
      margin-left: 5px;
      font-weight: normal;
    }
    .ttl-fresh { background: rgba(0, 255, 136, 0.25); color: #7fdfb0; }
    .ttl-warning { background: rgba(255, 170, 0, 0.25); color: #d4a852; }
    .ttl-critical { background: rgba(255, 68, 68, 0.25); color: #e08080; }
    .player-ttl {
      font-size: 0.65em;
      color: #888;
      margin-top: 2px;
    }
    .server-ttl {
      font-size: 0.8em;
      margin-left: 10px;
    }
    .pagination {
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 15px;
      margin-top: 20px;
      padding: 15px;
    }
    .pagination button {
      background: rgba(0, 212, 255, 0.2);
      border: 1px solid rgba(0, 212, 255, 0.3);
      color: #00d4ff;
      padding: 8px 16px;
      border-radius: 5px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .pagination button:hover:not(:disabled) {
      background: rgba(0, 212, 255, 0.3);
    }
    .pagination button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }
    .pagination span {
      color: #888;
      font-size: 0.9em;
    }
    .launcher-stat {
      background: rgba(138, 43, 226, 0.1);
      border-color: rgba(138, 43, 226, 0.3);
    }
    .launcher-stat .stat-value {
      color: #b388ff;
    }
    .refresh-btn {
      background: linear-gradient(135deg, #00d4ff, #0099cc);
      border: none;
      color: #fff;
      padding: 12px 30px;
      border-radius: 25px;
      cursor: pointer;
      font-size: 1em;
      font-weight: bold;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .refresh-btn:hover {
      transform: scale(1.05);
      box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4);
    }
    .refresh-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .last-update { color: #666; font-size: 0.85em; margin-top: 10px; }
    .no-data { color: #666; font-style: italic; padding: 20px; text-align: center; }
    .redis-status {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    /* Login styles */
    .login-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.9);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
    }
    .login-box {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      border: 1px solid rgba(0, 212, 255, 0.3);
      border-radius: 12px;
      padding: 40px;
      text-align: center;
      max-width: 400px;
      width: 90%;
    }
    .login-box h2 {
      color: #00d4ff;
      margin-bottom: 20px;
    }
    .login-box input {
      width: 100%;
      padding: 12px;
      border-radius: 5px;
      border: 1px solid #333;
      background: #0d0d1a;
      color: #fff;
      margin-bottom: 15px;
      font-size: 1em;
    }
    .login-box button {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #00d4ff, #0099cc);
      border: none;
      border-radius: 5px;
      color: #fff;
      font-size: 1em;
      font-weight: bold;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .login-box button:hover {
      transform: scale(1.02);
    }
    .login-error {
      color: #ff6b6b;
      margin-top: 10px;
      font-size: 0.9em;
    }
    .logout-btn {
      position: fixed;
      top: 20px;
      right: 20px;
      background: rgba(255, 100, 100, 0.2);
      border: 1px solid rgba(255, 100, 100, 0.3);
      color: #ff6b6b;
      padding: 8px 16px;
      border-radius: 5px;
      cursor: pointer;
      font-size: 0.85em;
      z-index: 100;
    }
    .logout-btn:hover {
      background: rgba(255, 100, 100, 0.3);
    }
    .hidden { display: none !important; }
  </style>
</head>
<body>
  <!-- Login Overlay -->
  <div class="login-overlay" id="loginOverlay">
    <div class="login-box">
      <h2>Admin Login</h2>
      <form id="loginForm">
        <input type="password" id="loginPassword" placeholder="Enter admin password" autocomplete="current-password" required>
        <button type="submit">Login</button>
      </form>
      <div class="login-error" id="loginError"></div>
    </div>
  </div>

  <button class="logout-btn hidden" id="logoutBtn" onclick="logout()">Logout</button>

  <div class="container hidden" id="mainContent">
    <h1>Hytale Auth Server</h1>

    <div class="stats-grid">
      <div class="stat-card launcher-stat">
        <div class="stat-value" id="launcherOnline">-</div>
        <div class="stat-label">Launcher Online</div>
      </div>
      <div class="stat-card launcher-stat">
        <div class="stat-value" id="launcherPeak">-</div>
        <div class="stat-label">Launcher Peak</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="playerCount">-</div>
        <div class="stat-label">Active Players</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="serverCount">-</div>
        <div class="stat-label">Active Servers</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="sessionCount">-</div>
        <div class="stat-label">Total Sessions</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="userCount">-</div>
        <div class="stat-label">Registered Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="prerenderCached">-</div>
        <div class="stat-label">Heads Cached</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="prerenderQueue">-</div>
        <div class="stat-label">Prerender Queue</div>
      </div>
    </div>

    <div class="section">
      <h2><span class="status-dot" id="redisStatus"></span>Redis Status</h2>
      <div id="redisInfo">Loading...</div>
    </div>

    <div class="section">
      <h2>Active Servers</h2>
      <div id="serversList">Loading...</div>
    </div>

    <div class="section">
      <h2>Set Server Name</h2>
      <form id="serverNameForm" style="display: flex; gap: 10px; flex-wrap: wrap; align-items: flex-end;">
        <div style="flex: 1; min-width: 200px;">
          <label style="display: block; margin-bottom: 5px; color: #888; font-size: 0.9em;">Server ID (audience)</label>
          <input type="text" id="serverAudience" placeholder="e.g. abc123-..." style="width: 100%; padding: 10px; border-radius: 5px; border: 1px solid #333; background: #1a1a2e; color: #fff;" required>
        </div>
        <div style="flex: 1; min-width: 150px;">
          <label style="display: block; margin-bottom: 5px; color: #888; font-size: 0.9em;">Display Name</label>
          <input type="text" id="serverDisplayName" placeholder="e.g. Main Server" style="width: 100%; padding: 10px; border-radius: 5px; border: 1px solid #333; background: #1a1a2e; color: #fff;" required>
        </div>
        <button type="submit" class="refresh-btn" style="padding: 10px 20px;">Set Name</button>
      </form>
      <div id="serverNameResult" style="margin-top: 10px; font-size: 0.9em;"></div>
    </div>

    <div style="text-align: center; margin-top: 20px;">
      <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
      <div class="last-update">Last update: <span id="lastUpdate">-</span></div>
    </div>
  </div>

  <script>
    let currentPage = 1;
    const pageLimit = 10;
    let adminToken = localStorage.getItem('adminToken');
    let savedPassword = localStorage.getItem('adminPassword');

    // Auth helper - adds token to fetch requests
    async function authFetch(url, options = {}) {
      if (!adminToken) throw new Error('Not authenticated');
      options.headers = options.headers || {};
      options.headers['X-Admin-Token'] = adminToken;
      const res = await fetch(url, options);
      if (res.status === 401) {
        // Token invalid, try auto-login with saved password
        if (savedPassword && await tryAutoLogin()) {
          // Retry the request with new token
          options.headers['X-Admin-Token'] = adminToken;
          return fetch(url, options);
        }
        logout();
        throw new Error('Session expired');
      }
      return res;
    }

    // Try to login with saved password
    async function tryAutoLogin() {
      if (!savedPassword) return false;
      try {
        const res = await fetch('/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: savedPassword })
        });
        const data = await res.json();
        if (res.ok && data.token) {
          adminToken = data.token;
          localStorage.setItem('adminToken', adminToken);
          return true;
        }
      } catch (e) {}
      return false;
    }

    // Check if we're authenticated
    async function checkAuth() {
      if (!adminToken) {
        // Try auto-login with saved password
        if (savedPassword) {
          return await tryAutoLogin();
        }
        return false;
      }
      try {
        const res = await fetch('/admin/verify', {
          headers: { 'X-Admin-Token': adminToken }
        });
        const data = await res.json();
        if (data.valid === true) return true;
        // Token invalid, try auto-login
        if (savedPassword) {
          return await tryAutoLogin();
        }
        return false;
      } catch (e) {
        return false;
      }
    }

    // Login handler
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('loginPassword').value;
      const rememberMe = document.getElementById('rememberMe')?.checked ?? true;
      const errorDiv = document.getElementById('loginError');
      errorDiv.textContent = '';

      try {
        const res = await fetch('/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        const data = await res.json();

        if (res.ok && data.token) {
          adminToken = data.token;
          localStorage.setItem('adminToken', adminToken);
          if (rememberMe) {
            savedPassword = password;
            localStorage.setItem('adminPassword', password);
          }
          showDashboard();
        } else {
          errorDiv.textContent = data.error || 'Login failed';
        }
      } catch (e) {
        errorDiv.textContent = 'Connection error';
      }
    });

    // Logout handler
    function logout() {
      adminToken = null;
      savedPassword = null;
      localStorage.removeItem('adminToken');
      localStorage.removeItem('adminPassword');
      document.getElementById('loginOverlay').classList.remove('hidden');
      document.getElementById('mainContent').classList.add('hidden');
      document.getElementById('logoutBtn').classList.add('hidden');
      document.getElementById('loginPassword').value = '';
    }

    // Show dashboard after login
    function showDashboard() {
      document.getElementById('loginOverlay').classList.add('hidden');
      document.getElementById('mainContent').classList.remove('hidden');
      document.getElementById('logoutBtn').classList.remove('hidden');
      refreshData();
    }

    // Initialize - check auth on page load
    (async () => {
      if (await checkAuth()) {
        showDashboard();
      } else {
        adminToken = null;
        localStorage.removeItem('adminToken');
      }
    })();

    // Helper function to get TTL status class and text
    function getTtlStatus(ttlSeconds) {
      const hours = ttlSeconds / 3600;
      if (hours > 5) return { class: 'ttl-fresh', text: Math.round(hours) + 'h' };
      if (hours > 1) return { class: 'ttl-warning', text: Math.round(hours * 10) / 10 + 'h' };
      if (ttlSeconds > 60) return { class: 'ttl-critical', text: Math.round(ttlSeconds / 60) + 'm' };
      return { class: 'ttl-critical', text: ttlSeconds + 's' };
    }

    async function refreshData() {
      const btn = document.querySelector('.refresh-btn');
      btn.disabled = true;
      btn.textContent = 'Loading...';

      try {
        // Fetch launcher stats
        try {
          const launcherRes = await fetch('https://api.hytalef2p.com/api/players/stats');
          const launcher = await launcherRes.json();
          document.getElementById('launcherOnline').textContent = launcher.online || 0;
          document.getElementById('launcherPeak').textContent = launcher.peak || 0;
        } catch (e) {
          document.getElementById('launcherOnline').textContent = '?';
          document.getElementById('launcherPeak').textContent = '?';
        }

        // Fetch stats (lightweight)
        const statsRes = await authFetch('/admin/stats');
        const stats = await statsRes.json();
        
        // Update stats
        document.getElementById('playerCount').textContent = stats.activePlayers || 0;
        document.getElementById('serverCount').textContent = stats.activeServers || 0;
        document.getElementById('sessionCount').textContent = stats.activeSessions || 0;
        document.getElementById('userCount').textContent = stats.keys?.users || 0;
        // Update Redis status
        const redisStatus = document.getElementById('redisStatus');
        const redisInfo = document.getElementById('redisInfo');
        if (stats.redis?.connected) {
          redisStatus.className = 'status-dot online';
          redisInfo.innerHTML = \`
            <div class="redis-status">
              <strong>Connected</strong> |
              Sessions: \${stats.keys?.sessions || 0} |
              Auth Grants: \${stats.keys?.authGrants || 0} |
              Users: \${stats.keys?.users || 0}
            </div>
          \`;
        } else {
          redisStatus.className = 'status-dot offline';
          redisInfo.textContent = 'Not connected - data will not persist!';
        }

        // Fetch servers (paginated)
        await loadServers(currentPage);

        // Fetch prerender queue stats
        try {
          const prerenderRes = await authFetch('/admin/prerender-queue');
          const prerender = await prerenderRes.json();
          document.getElementById('prerenderCached').textContent = prerender.totalCachedFiles || 0;
          document.getElementById('prerenderQueue').textContent = prerender.uncached || 0;
        } catch (e) {
          document.getElementById('prerenderCached').textContent = '?';
          document.getElementById('prerenderQueue').textContent = '?';
        }

        // Update timestamp
        document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();

      } catch (e) {
        console.error('Failed to fetch stats:', e);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Refresh Data';
      }
    }

    async function loadServers(page) {
      const serversList = document.getElementById('serversList');
      serversList.innerHTML = '<div class="no-data">Loading servers...</div>';

      try {
        const res = await authFetch(\`/admin/servers?page=\${page}&limit=\${pageLimit}\`);
        const data = await res.json();

        if (data.servers && data.servers.length > 0) {
          let html = data.servers.map(server => {
            const minTtl = server.players && server.players.length > 0
              ? Math.min(...server.players.map(p => p.ttl || 0))
              : 0;
            const serverTtlStatus = getTtlStatus(minTtl);
            const serverId = 'server-' + server.audience.replace(/[^a-zA-Z0-9]/g, '');

            return \`
            <div class="server-card">
              <div class="server-header">
                <span class="server-name">
                  \${server.name || server.audience || 'Unknown Server'}
                  <span class="ttl-badge \${serverTtlStatus.class} server-ttl">\${serverTtlStatus.text}</span>
                </span>
                <span class="player-count">\${server.playerCount} player\${server.playerCount !== 1 ? 's' : ''}</span>
              </div>
              \${server.name ? \`<div class="server-audience">ID: \${server.audience}</div>\` : ''}
              \${server.players && server.players.length > 0 ? \`
                <div class="players-list" id="\${serverId}">
                  \${server.players.map(p => {
                    const ttlStatus = getTtlStatus(p.ttl || 0);
                    return \`
                    <div class="player-tag">
                      <iframe class="player-avatar" src="/avatar/\${p.uuid}/head?bg=black" loading="lazy" title="\${p.username}"></iframe>
                      <div class="player-info">
                        <span class="player-name">\${p.username} <span class="ttl-badge \${ttlStatus.class}">\${ttlStatus.text}</span></span>
                        <span class="uuid">\${p.uuid.substring(0, 8)}...</span>
                      </div>
                    </div>
                  \`}).join('')}
                </div>
              \` : ''}
            </div>
          \`}).join('');

          // Add pagination controls
          const pg = data.pagination;
          html += \`
            <div class="pagination">
              <button onclick="changePage(\${pg.page - 1})" \${!pg.hasPrev ? 'disabled' : ''}>Previous</button>
              <span>Page \${pg.page} of \${pg.totalPages} (\${pg.totalServers} servers)</span>
              <button onclick="changePage(\${pg.page + 1})" \${!pg.hasNext ? 'disabled' : ''}>Next</button>
            </div>
          \`;

          serversList.innerHTML = html;
        } else {
          serversList.innerHTML = '<div class="no-data">No active servers</div>';
        }
      } catch (e) {
        serversList.innerHTML = '<div class="no-data">Failed to load servers</div>';
      }
    }

    function changePage(page) {
      if (page < 1) return;
      currentPage = page;
      loadServers(page);
    }

    // Initial load
    refreshData();

    // Auto-refresh every 60 seconds
    setInterval(refreshData, 60000);

    // Server name form handler
    document.getElementById('serverNameForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const audience = document.getElementById('serverAudience').value.trim();
      const name = document.getElementById('serverDisplayName').value.trim();
      const resultDiv = document.getElementById('serverNameResult');

      if (!audience || !name) {
        resultDiv.innerHTML = '<span style="color: #ff6b6b;">Please fill in both fields</span>';
        return;
      }

      try {
        const res = await authFetch('/admin/server-name', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ audience, name })
        });
        const data = await res.json();

        if (data.success) {
          resultDiv.innerHTML = '<span style="color: #00d4ff;">Server name set successfully!</span>';
          document.getElementById('serverAudience').value = '';
          document.getElementById('serverDisplayName').value = '';
          refreshData();
        } else {
          resultDiv.innerHTML = '<span style="color: #ff6b6b;">Error: ' + (data.error || 'Unknown error') + '</span>';
        }
      } catch (err) {
        resultDiv.innerHTML = '<span style="color: #ff6b6b;">Request failed: ' + err.message + '</span>';
      }
    });
  </script>
</body>
</html>`;

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(html);
}

function handleSession(req, res, body, uuid, name) {
  sendJson(res, 200, {
    success: true,
    session_id: crypto.randomUUID(),
    identityToken: generateIdentityToken(uuid, name),
    identity_token: generateIdentityToken(uuid, name),
    sessionToken: generateSessionToken(uuid),
    session_token: generateSessionToken(uuid),
    expires_in: 86400,
    token_type: 'Bearer',
    user: { uuid, name, premium: true }
  });
}

function handleAuth(req, res, body, uuid, name) {
  sendJson(res, 200, {
    success: true,
    authenticated: true,
    identity_token: generateIdentityToken(uuid, name),
    session_token: generateSessionToken(uuid),
    token_type: 'Bearer',
    expires_in: 86400,
    user: { uuid, name, premium: true }
  });
}

function handleToken(req, res, body, uuid, name) {
  sendJson(res, 200, {
    access_token: generateIdentityToken(uuid, name),
    identity_token: generateIdentityToken(uuid, name),
    session_token: generateSessionToken(uuid),
    token_type: 'Bearer',
    expires_in: 86400,
    refresh_token: generateSessionToken(uuid)
  });
}

function handleValidate(req, res, body, uuid, name) {
  sendJson(res, 200, {
    valid: true,
    success: true,
    user: { uuid, name, premium: true }
  });
}

function handleRefresh(req, res, body, uuid, name) {
  sendJson(res, 200, {
    success: true,
    identity_token: generateIdentityToken(uuid, name),
    session_token: generateSessionToken(uuid),
    token_type: 'Bearer',
    expires_in: 86400
  });
}

function handleProfile(req, res, body, uuid, name) {
  sendJson(res, 200, {
    success: true,
    uuid, name,
    display_name: name,
    premium: true,
    created_at: '2024-01-01T00:00:00Z',
    settings: { language: 'en', notifications: true },
    stats: { playtime: 0, worlds_created: 0 }
  });
}

// Profile lookup by UUID - used by ProfileServiceClient.getProfileByUuid()
// Returns PublicGameProfile format: { uuid, username }
async function handleProfileLookupByUuid(req, res, lookupUuid, headers) {
  const serverAudience = extractServerAudienceFromHeaders(headers);
  console.log('Profile lookup by UUID:', lookupUuid, serverAudience ? `(server: ${serverAudience})` : '(no server context)');

  // Try to find username in our caches and storage
  let username = null;

  // First, check if player is active on this server (most accurate)
  if (serverAudience) {
    const players = await getPlayersOnServer(serverAudience);
    const activePlayer = players.find(p => p.uuid === lookupUuid);
    if (activePlayer) {
      username = activePlayer.username;
      console.log(`Found active player on server: ${username}`);
    }
  }

  // Check in-memory cache first
  if (!username && uuidUsernameCache.has(lookupUuid)) {
    username = uuidUsernameCache.get(lookupUuid);
  }

  // Check Redis for persisted username
  if (!username) {
    username = await getUsername(lookupUuid);
  }

  // If not found, return a generic name based on UUID
  // This ensures commands like /ban <uuid> always work
  if (!username) {
    username = `Player_${lookupUuid.substring(0, 8)}`;
    console.log(`UUID ${lookupUuid} not found in records, returning generic name`);
  }

  sendJson(res, 200, {
    uuid: lookupUuid,
    username: username
  });
}

// Profile lookup by username - used by ProfileServiceClient.getProfileByUsername()
// Returns PublicGameProfile format: { uuid, username }
// Server-scoped: First looks for the player on the requesting server, then falls back to global search.
// This prevents issues with duplicate usernames across different servers.
async function handleProfileLookupByUsername(req, res, lookupUsername, headers) {
  const serverAudience = extractServerAudienceFromHeaders(headers);
  console.log('Profile lookup by username:', lookupUsername, serverAudience ? `(server: ${serverAudience})` : '(no server context)');

  // PRIORITY 1: Check active players on this specific server
  // This is the most accurate for commands like /ban <username> on a specific server
  if (serverAudience) {
    const serverMatches = await findPlayerOnServer(serverAudience, lookupUsername);
    if (serverMatches.length === 1) {
      console.log(`Found unique player "${lookupUsername}" on server ${serverAudience}: ${serverMatches[0].uuid}`);
      sendJson(res, 200, {
        uuid: serverMatches[0].uuid,
        username: serverMatches[0].username
      });
      return;
    } else if (serverMatches.length > 1) {
      // Multiple players with same username on same server - pick first (shouldn't happen often)
      console.log(`Multiple players with username "${lookupUsername}" on server ${serverAudience}, returning first: ${serverMatches[0].uuid}`);
      sendJson(res, 200, {
        uuid: serverMatches[0].uuid,
        username: serverMatches[0].username
      });
      return;
    }
    // No match on this server, fall through to global search
    console.log(`Player "${lookupUsername}" not found on server ${serverAudience}, searching globally`);
  }

  // PRIORITY 2: Global search - check local cache first, then scan all sessions
  const matches = [];

  // Check in-memory cache (fastest)
  for (const [uuid, name] of uuidUsernameCache.entries()) {
    if (name.toLowerCase() === lookupUsername.toLowerCase()) {
      matches.push({
        uuid,
        username: name,
        lastSeen: new Date().toISOString() // Currently in cache, so recent
      });
    }
  }

  // If Redis is connected, scan for more matches in all sessions
  if (redisConnected && matches.length === 0) {
    try {
      // Get all sessions and search for username
      const { sessions } = await getAllActiveSessions();
      for (const session of sessions) {
        if (session.username && session.username.toLowerCase() === lookupUsername.toLowerCase()) {
          if (!matches.find(m => m.uuid === session.uuid)) {
            matches.push({
              uuid: session.uuid,
              username: session.username,
              lastSeen: session.createdAt || new Date().toISOString()
            });
          }
        }
      }
    } catch (e) {
      console.error('Failed to search sessions:', e.message);
    }
  }

  if (matches.length === 0) {
    // Username not found - return 404
    console.log('Username not found:', lookupUsername);
    sendJson(res, 404, {
      error: 'Profile not found',
      message: `No profile found for username: ${lookupUsername}`
    });
    return;
  }

  if (matches.length > 1) {
    console.log(`Multiple players with username "${lookupUsername}" globally: ${matches.map(m => m.uuid).join(', ')}`);
    // Sort by lastSeen descending (most recent first)
    matches.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
  }

  // Return the most recently seen player with this username
  const bestMatch = matches[0];
  console.log(`Returning profile for "${lookupUsername}": ${bestMatch.uuid} (${matches.length} total global matches)`);

  sendJson(res, 200, {
    uuid: bestMatch.uuid,
    username: bestMatch.username
  });
}

async function handleSkin(req, res, body, uuid, name) {
  console.log('skin update:', uuid);

  // Get existing user data and update skin
  const existingData = await getUserData(uuid);
  existingData.skin = body;
  existingData.lastUpdated = new Date().toISOString();
  await saveUserData(uuid, existingData);

  // Invalidate head image cache since skin changed
  invalidateHeadCache(uuid);

  res.writeHead(204);
  res.end();
}

function handleLauncherData(req, res, body, uuid, name) {
  sendJson(res, 200, {
    EulaAcceptedAt: "2024-01-01T00:00:00Z",
    Owner: uuid,
    Patchlines: {
      PreRelease: { BuildVersion: "1.0.0", Newest: 1 },
      Release: { BuildVersion: "1.0.0", Newest: 1 }
    },
    Profiles: [{
      UUID: uuid,
      Username: name,
      Entitlements: ["game.base"]
    }]
  });
}

async function handleGameProfile(req, res, body, uuid, name) {
  const nextNameChange = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  let skin = null;
  const userDataObj = await getUserData(uuid);
  if (userDataObj && userDataObj.skin) {
    skin = JSON.stringify(userDataObj.skin);
  }

  sendJson(res, 200, {
    uuid, username: name,
    entitlements: ["game.base"],
    createdAt: "2024-01-01T00:00:00Z",
    nextNameChangeAt: nextNameChange,
    skin: skin
  });
}

// Get all profiles for the authenticated user (used by hytale-server client)
function handleGetProfiles(req, res, body, uuid, name) {
  console.log('get-profiles:', uuid, name);

  sendJson(res, 200, {
    profiles: [{
      uuid: uuid,
      username: name,
      entitlements: ["game.base"]
    }]
  });
}

function handleCosmetics(req, res, body, uuid, name) {
  // Try to load cosmetics from Assets.zip first
  const assetsCosmetics = loadCosmeticsFromAssets();

  if (assetsCosmetics && Object.keys(assetsCosmetics).length > 0) {
    console.log('Returning cosmetics from Assets.zip');
    sendJson(res, 200, assetsCosmetics);
    return;
  }

  // Fallback to basic cosmetics if Assets.zip not available
  console.log('Using fallback cosmetics');
  sendJson(res, 200, {
    bodyCharacteristic: ["Default", "Muscular"],
    cape: ["Cape_Royal_Emissary", "Cape_New_Beginning", "Cape_Forest_Guardian", "Cape_PopStar"],
    earAccessory: [],
    ears: [],
    eyebrows: [],
    eyes: [],
    face: [],
    faceAccessory: [],
    facialHair: [],
    gloves: [],
    haircut: [],
    headAccessory: [],
    mouth: [],
    overpants: [],
    overtop: [],
    pants: [],
    shoes: [],
    skinFeature: [],
    undertop: [],
    underwear: []
  });
}

function sendJson(res, status, data, req = null) {
  const json = JSON.stringify(data);

  // Check if client accepts gzip and response is large enough to benefit
  const acceptEncoding = req?.headers?.['accept-encoding'] || '';
  if (acceptEncoding.includes('gzip') && json.length > 1024) {
    zlib.gzip(json, (err, compressed) => {
      if (err) {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(json);
      } else {
        res.writeHead(status, {
          'Content-Type': 'application/json',
          'Content-Encoding': 'gzip'
        });
        res.end(compressed);
      }
    });
  } else {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(json);
  }
}

// Handle avatar viewer routes
function handleAvatarRoutes(req, res, urlPath, body = {}) {
  // Parse UUID from path: /avatar/{uuid} or /avatar/{uuid}/model or /avatar/{uuid}/head
  const pathParts = urlPath.split('/').filter(p => p);

  if (pathParts.length < 2) {
    sendJson(res, 400, { error: 'UUID required' });
    return;
  }

  const uuid = pathParts[1];
  const action = pathParts[2]; // 'model', 'head', or undefined (serve HTML)

  if (action === 'model') {
    // Return model data for Three.js rendering
    handleAvatarModel(req, res, uuid);
  } else if (action === 'preview') {
    // Handle preview with custom skin data (POST)
    handleAvatarPreview(req, res, uuid, body);
  } else if (action === 'head') {
    // Return embeddable head (cached image or render page)
    serveHeadEmbed(req, res, uuid);
  } else if (action === 'head-cache' && req.method === 'POST') {
    // Receive rendered head image for caching
    handleHeadImageCache(req, res, uuid);
  } else {
    // Serve the HTML viewer page
    serveAvatarViewer(req, res, uuid);
  }
}

// Serve avatar viewer HTML page
function serveAvatarViewer(req, res, uuid) {
  const viewerPath = path.join(__dirname, 'assets', 'avatar-viewer.html');

  // Check if custom viewer exists
  if (fs.existsSync(viewerPath)) {
    let html = fs.readFileSync(viewerPath, 'utf8');
    // Inject UUID into the page
    html = html.replace('{{UUID}}', uuid);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
    return;
  }

  // Serve embedded viewer
  const html = generateAvatarViewerHtml(uuid);
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(html);
}

// Head image cache - disk-only storage (no memory)
const HEAD_CACHE_TTL = 3600000; // 1 hour cache TTL
const HEAD_CACHE_DIR = path.join(DATA_DIR, 'head-cache');

// Initialize head cache directory
function initHeadCache() {
  try {
    if (!fs.existsSync(HEAD_CACHE_DIR)) {
      fs.mkdirSync(HEAD_CACHE_DIR, { recursive: true });
      console.log(`Created head cache directory: ${HEAD_CACHE_DIR}`);
    }
  } catch (err) {
    console.error('Error initializing head cache:', err.message);
  }
}

// Get cached head image from disk (returns null if not found or expired)
// Returns { data: Buffer, mtime: Date } or null
function getHeadCacheFromDisk(cacheKey) {
  try {
    const filePath = path.join(HEAD_CACHE_DIR, `${cacheKey}.png`);
    if (!fs.existsSync(filePath)) return null;

    const stats = fs.statSync(filePath);
    const age = Date.now() - stats.mtimeMs;

    // Expired - delete and return null
    if (age > HEAD_CACHE_TTL) {
      fs.unlinkSync(filePath);
      return null;
    }

    return {
      data: fs.readFileSync(filePath),
      mtime: stats.mtime
    };
  } catch (err) {
    return null;
  }
}

// Save head image to disk
function saveHeadCacheToDisk(cacheKey, data) {
  try {
    const filePath = path.join(HEAD_CACHE_DIR, `${cacheKey}.png`);
    fs.writeFileSync(filePath, data);
  } catch (err) {
    console.error('Error saving head cache to disk:', err.message);
  }
}

// Delete head cache files for a user
function deleteHeadCacheFromDisk(uuid) {
  try {
    const files = fs.readdirSync(HEAD_CACHE_DIR);
    for (const file of files) {
      if (file.startsWith(uuid + '_')) {
        fs.unlinkSync(path.join(HEAD_CACHE_DIR, file));
      }
    }
  } catch (err) {
    console.error('Error deleting head cache from disk:', err.message);
  }
}

// Initialize cache on module load
initHeadCache();

// Serve embeddable head viewer - either cached image or render page
// Supports query params: ?bg=transparent|white|black|#hexcolor&nocache=1
async function serveHeadEmbed(req, res, uuid) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const bgParam = url.searchParams.get('bg') || 'black';
  const noCache = url.searchParams.get('nocache') === '1';
  const cacheKey = `${uuid}_${bgParam}`;

  // Check disk cache first (unless nocache is set)
  if (!noCache) {
    const cached = getHeadCacheFromDisk(cacheKey);
    if (cached) {
      const lastModified = cached.mtime.toUTCString();
      const etag = `"${cacheKey}-${cached.mtime.getTime()}"`;

      // Check If-None-Match (ETag) header
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304);
        res.end();
        return;
      }

      // Check If-Modified-Since header
      const ifModifiedSince = req.headers['if-modified-since'];
      if (ifModifiedSince && new Date(ifModifiedSince) >= cached.mtime) {
        res.writeHead(304);
        res.end();
        return;
      }

      // Serve cached PNG image from disk with proper caching headers
      res.writeHead(200, {
        'Content-Type': 'image/png',
        'Content-Length': cached.data.length,
        'Cache-Control': 'public, max-age=3600',
        'ETag': etag,
        'Last-Modified': lastModified,
        'X-Cache': 'HIT'
      });
      res.end(cached.data);
      return;
    }
  }

  // No cache, serve HTML that will render and cache the image
  const html = generateHeadEmbedHtml(uuid, bgParam);
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(html);
}

// Receive rendered head image from client and cache it
function handleHeadImageCache(req, res, uuid, url) {
  if (!url) url = new URL(req.url, `http://${req.headers.host}`);
  const bgParam = url.searchParams.get('bg') || 'black';
  const cacheKey = `${uuid}_${bgParam}`;
  console.log(`Caching head image for ${cacheKey}`);

  let body = [];
  req.on('data', chunk => body.push(chunk));
  req.on('end', () => {
    try {
      const data = Buffer.concat(body);

      // Validate it's a PNG (starts with PNG signature)
      if (data.length > 8 && data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4E && data[3] === 0x47) {
        // Save to disk only (no memory cache)
        saveHeadCacheToDisk(cacheKey, data);
        sendJson(res, 200, { success: true, cached: true });
      } else {
        sendJson(res, 400, { error: 'Invalid PNG data' });
      }
    } catch (err) {
      sendJson(res, 500, { error: err.message });
    }
  });
}

// Invalidate head cache for a user (call when skin changes)
function invalidateHeadCache(uuid) {
  deleteHeadCacheFromDisk(uuid);
}

// Generate minimal HTML for head-only 3D renderer (for embedding)
// bgParam: 'transparent', 'white', 'black', or hex color like '#ff0000'
function generateHeadEmbedHtml(uuid, bgParam = 'transparent') {
  // Parse background parameter
  let cssBg = 'transparent';
  let threeColor = '0x000000';
  let threeAlpha = '0'; // 0 = transparent

  if (bgParam === 'transparent') {
    cssBg = 'transparent';
    threeAlpha = '0';
  } else if (bgParam === 'white') {
    cssBg = '#ffffff';
    threeColor = '0xffffff';
    threeAlpha = '1';
  } else if (bgParam === 'black') {
    cssBg = '#000000';
    threeColor = '0x000000';
    threeAlpha = '1';
  } else if (bgParam.startsWith('#')) {
    // Custom hex color
    cssBg = bgParam;
    threeColor = '0x' + bgParam.slice(1);
    threeAlpha = '1';
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Head - ${uuid}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: 100%; height: 100%; overflow: hidden; background: ${cssBg}; }
    #canvas-container { width: 100%; height: 100%; }
    canvas { display: block; width: 100%; height: 100%; }
  </style>
</head>
<body>
  <div id="canvas-container"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
  <script src="/assets/avatar.js"></script>
  <script>
    const UUID = '${uuid}';
    const BG_COLOR = ${threeColor};
    const BG_ALPHA = ${threeAlpha};

    async function init() {
      const container = document.getElementById('canvas-container');

      const viewer = new HytaleAvatarViewer(container, {
        autoRotate: false,
        showGrid: false,
        backgroundColor: BG_COLOR,
        alpha: true  // Enable transparency support
      });

      viewer.init();

      // Set background based on parameters
      viewer.renderer.setClearColor(BG_COLOR, BG_ALPHA);
      if (BG_ALPHA === 0) {
        viewer.scene.background = null;
      } else {
        viewer.scene.background = new THREE.Color(BG_COLOR);
      }

      try {
        await viewer.loadAvatar(UUID);

        // Camera position for head view (facing camera)
        // Pos: (0, 1.1, -1.0), LookAt Y: 1.0, FOV: 40
        viewer.camera.position.set(0, 1.1, -1.0);
        viewer.camera.lookAt(0, 1.0, 0);
        viewer.camera.fov = 40;
        viewer.camera.updateProjectionMatrix();

        // Disable animation for static head
        viewer.animationEnabled = false;
        viewer.autoRotate = false;
        await viewer.setAnimation(null);

        // Render once
        viewer.renderer.render(viewer.scene, viewer.camera);

        // Cache the rendered image on the server
        cacheRenderedImage(viewer.renderer.domElement);
      } catch (err) {
        console.error('Head embed error:', err);
      }
    }

    // Send rendered image to server for caching
    async function cacheRenderedImage(canvas) {
      try {
        const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
        await fetch('/avatar/' + UUID + '/head-cache?bg=${bgParam}', {
          method: 'POST',
          body: blob,
          headers: { 'Content-Type': 'image/png' }
        });
      } catch (err) {
        console.log('Cache upload failed (non-critical):', err);
      }
    }

    init();
  </script>
</body>
</html>`;
}

// Test page for head embed - styled like admin player badges
function handleTestHeadPage(req, res) {
  const testUuid = '62ab5527-60d1-4031-942f-b292b5144b4f';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Head Embed Test</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      padding: 40px;
      color: #e0e0e0;
    }
    h1 {
      color: #00d4ff;
      margin-bottom: 30px;
      font-size: 1.8em;
    }
    h2 {
      color: #888;
      margin: 30px 0 15px;
      font-size: 1.1em;
    }
    .container {
      max-width: 800px;
      margin: 0 auto;
    }
    .section {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 20px;
    }

    /* Player tag styles - same as admin */
    .players-list {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .player-tag {
      background: rgba(255, 255, 255, 0.1);
      padding: 6px 12px;
      border-radius: 15px;
      font-size: 0.85em;
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 8px;
    }
    .player-tag .player-avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: rgba(0, 0, 0, 0.3);
      flex-shrink: 0;
      overflow: hidden;
      border: none;
    }
    .player-tag .player-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .player-tag .player-name {
      color: #fff;
      font-weight: 500;
    }
    .player-tag .uuid {
      color: #666;
      font-size: 0.7em;
      font-family: monospace;
    }
    .ttl-badge {
      font-size: 0.7em;
      padding: 2px 6px;
      border-radius: 3px;
      margin-left: 5px;
    }
    .ttl-fresh { background: rgba(0, 255, 136, 0.25); color: #7fdfb0; }

    /* Larger player tag variant */
    .player-tag-large {
      background: rgba(255, 255, 255, 0.1);
      padding: 12px 20px;
      border-radius: 20px;
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 15px;
    }
    .player-tag-large .player-avatar {
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: rgba(0, 0, 0, 0.3);
      flex-shrink: 0;
      overflow: hidden;
      border: none;
    }
    .player-tag-large .player-info {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .player-tag-large .player-name {
      color: #fff;
      font-weight: 600;
      font-size: 1.2em;
    }
    .player-tag-large .uuid {
      color: #666;
      font-size: 0.8em;
      font-family: monospace;
    }

    /* Direct iframe preview */
    .iframe-preview {
      display: flex;
      gap: 20px;
      align-items: center;
      flex-wrap: wrap;
    }
    .iframe-box {
      text-align: center;
    }
    .iframe-box label {
      display: block;
      margin-bottom: 10px;
      color: #888;
      font-size: 0.9em;
    }
    .iframe-box iframe {
      border: 1px dashed rgba(255,255,255,0.2);
      background: rgba(0,0,0,0.3);
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Head Embed Test</h1>

    <div class="section">
      <h2>Background variants (64x64)</h2>
      <p style="color: #888; margin-bottom: 15px; font-size: 0.9em;">Use ?bg=transparent|white|black|#hexcolor</p>
      <div class="iframe-preview">
        <div class="iframe-box">
          <label>?bg=transparent (default)</label>
          <iframe src="/avatar/${testUuid}/head?bg=transparent" width="64" height="64" frameborder="0"></iframe>
        </div>
        <div class="iframe-box">
          <label>?bg=white</label>
          <iframe src="/avatar/${testUuid}/head?bg=white" width="64" height="64" frameborder="0" style="background: #333;"></iframe>
        </div>
        <div class="iframe-box">
          <label>?bg=black</label>
          <iframe src="/avatar/${testUuid}/head?bg=black" width="64" height="64" frameborder="0"></iframe>
        </div>
        <div class="iframe-box">
          <label>?bg=#1a1a2e (dark blue)</label>
          <iframe src="/avatar/${testUuid}/head?bg=%231a1a2e" width="64" height="64" frameborder="0"></iframe>
        </div>
        <div class="iframe-box">
          <label>?bg=#00d4ff (cyan)</label>
          <iframe src="/avatar/${testUuid}/head?bg=%2300d4ff" width="64" height="64" frameborder="0"></iframe>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Size variants (transparent bg)</h2>
      <div class="iframe-preview">
        <div class="iframe-box">
          <label>128x128</label>
          <iframe src="/avatar/${testUuid}/head" width="128" height="128" frameborder="0"></iframe>
        </div>
        <div class="iframe-box">
          <label>64x64</label>
          <iframe src="/avatar/${testUuid}/head" width="64" height="64" frameborder="0"></iframe>
        </div>
        <div class="iframe-box">
          <label>40x40 (admin badge)</label>
          <iframe src="/avatar/${testUuid}/head" width="40" height="40" frameborder="0"></iframe>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Player badge (admin style - 40px avatar)</h2>
      <div class="players-list">
        <div class="player-tag">
          <iframe class="player-avatar" src="/avatar/${testUuid}/head" loading="lazy" title="TestPlayer"></iframe>
          <div class="player-info">
            <span class="player-name">TestPlayer <span class="ttl-badge ttl-fresh">9h 45m</span></span>
            <span class="uuid">${testUuid.substring(0, 8)}...</span>
          </div>
        </div>
        <div class="player-tag">
          <iframe class="player-avatar" src="/avatar/${testUuid}/head" loading="lazy" title="AnotherPlayer"></iframe>
          <div class="player-info">
            <span class="player-name">AnotherPlayer <span class="ttl-badge ttl-fresh">8h 30m</span></span>
            <span class="uuid">${testUuid.substring(0, 8)}...</span>
          </div>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Large player badge (64px avatar)</h2>
      <div class="player-tag-large">
        <iframe class="player-avatar" src="/avatar/${testUuid}/head" loading="lazy" title="TestPlayer"></iframe>
        <div class="player-info">
          <span class="player-name">TestPlayer</span>
          <span class="uuid">${testUuid}</span>
        </div>
      </div>
    </div>

    <div class="section" style="background: #ffffff;">
      <h2 style="color: #333;">On white background</h2>
      <div class="players-list">
        <div class="player-tag" style="background: rgba(0,0,0,0.1);">
          <iframe class="player-avatar" src="/avatar/${testUuid}/head" loading="lazy" title="TestPlayer"></iframe>
          <div class="player-info">
            <span class="player-name" style="color: #333;">TestPlayer</span>
            <span class="uuid" style="color: #999;">${testUuid.substring(0, 8)}...</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(html);
}

// Handle avatar model data request
async function handleAvatarModel(req, res, uuid) {
  // Get user skin data from Redis
  const userDataObj = await getUserData(uuid);
  const userSkin = userDataObj?.skin || null;

  if (!userSkin) {
    sendJson(res, 404, { error: 'User skin not found', uuid });
    return;
  }

  // Load configs
  const configs = loadCosmeticConfigs();
  const gradientSets = loadGradientSets();
  const eyeColors = loadEyeColors();

  if (!configs) {
    sendJson(res, 500, { error: 'Could not load cosmetic configs' });
    return;
  }

  // Resolve all skin parts to their model/texture paths
  const resolvedParts = {};
  const categories = [
    'haircut', 'pants', 'overtop', 'undertop', 'shoes',
    'headAccessory', 'faceAccessory', 'earAccessory',
    'eyebrows', 'eyes', 'face', 'facialHair', 'gloves',
    'cape', 'overpants', 'mouth', 'ears', 'underwear'
  ];

  for (const category of categories) {
    if (userSkin[category]) {
      const resolved = resolveSkinPart(category, userSkin[category], configs, gradientSets);
      if (resolved) {
        resolvedParts[category] = resolved;
      }
    }
  }

  // Handle eye color separately (it's stored in 'eyeColor' field)
  if (userSkin.eyeColor && eyeColors) {
    const eyeColorData = eyeColors[userSkin.eyeColor];
    if (eyeColorData && resolvedParts.eyes) {
      // Override the base color for eyes with the eye color
      resolvedParts.eyes.baseColor = eyeColorData.BaseColor;

      // Also resolve the gradient texture from Eyes_Gradient set
      if (resolvedParts.eyes.gradientSet && gradientSets) {
        const eyeGradientSet = gradientSets.find(g => g.Id === resolvedParts.eyes.gradientSet);
        if (eyeGradientSet && eyeGradientSet.Gradients && eyeGradientSet.Gradients[userSkin.eyeColor]) {
          resolvedParts.eyes.gradientTexture = eyeGradientSet.Gradients[userSkin.eyeColor].Texture;
        }
      }
    }
  }

  // Parse bodyCharacteristic for body type and skin tone
  // Format: "BodyType.SkinToneId" e.g., "Muscular.22"
  let bodyType = 'Regular';
  let skinTone = '01'; // Default to light peach

  if (userSkin.bodyCharacteristic) {
    const bodyParts = userSkin.bodyCharacteristic.split('.');
    bodyType = bodyParts[0] || 'Regular';
    if (bodyParts.length > 1) {
      // Pad single digit to two digits (e.g., "22" stays "22", "5" becomes "05")
      skinTone = bodyParts[1].padStart(2, '0');
    }
  }

  // Allow explicit skinTone override
  if (userSkin.skinTone) {
    skinTone = userSkin.skinTone;
  }

  sendJson(res, 200, {
    uuid,
    skinTone,
    bodyType,
    parts: resolvedParts,
    raw: userSkin
  });
}

// Handle avatar preview with custom skin data (POST)
function handleAvatarPreview(req, res, uuid, customSkin = {}) {
  if (req.method !== 'POST') {
    sendJson(res, 405, { error: 'Method not allowed, use POST' });
    return;
  }

  // Load configs
  const configs = loadCosmeticConfigs();
  const gradientSets = loadGradientSets();
  const eyeColors = loadEyeColors();

  if (!configs) {
    sendJson(res, 500, { error: 'Could not load cosmetic configs' });
    return;
  }

  // Resolve all skin parts to their model/texture paths
  const resolvedParts = {};
  const categories = [
    'haircut', 'pants', 'overtop', 'undertop', 'shoes',
    'headAccessory', 'faceAccessory', 'earAccessory',
    'eyebrows', 'eyes', 'face', 'facialHair', 'gloves',
    'cape', 'overpants', 'mouth', 'ears', 'underwear'
  ];

  for (const category of categories) {
    if (customSkin[category]) {
      const resolved = resolveSkinPart(category, customSkin[category], configs, gradientSets);
      if (resolved) {
        resolvedParts[category] = resolved;
      }
    }
  }

  // Handle eye color separately
  if (customSkin.eyeColor && eyeColors) {
    const eyeColorData = eyeColors[customSkin.eyeColor];
    if (eyeColorData && resolvedParts.eyes) {
      resolvedParts.eyes.baseColor = eyeColorData.BaseColor;

      if (resolvedParts.eyes.gradientSet && gradientSets) {
        const eyeGradientSet = gradientSets.find(g => g.Id === resolvedParts.eyes.gradientSet);
        if (eyeGradientSet && eyeGradientSet.Gradients && eyeGradientSet.Gradients[customSkin.eyeColor]) {
          resolvedParts.eyes.gradientTexture = eyeGradientSet.Gradients[customSkin.eyeColor].Texture;
        }
      }
    }
  }

  // Parse bodyCharacteristic for body type and skin tone
  let bodyType = 'Regular';
  let skinTone = '01';

  if (customSkin.bodyCharacteristic) {
    const bodyParts = customSkin.bodyCharacteristic.split('.');
    bodyType = bodyParts[0] || 'Regular';
    if (bodyParts.length > 1) {
      skinTone = bodyParts[1].padStart(2, '0');
    }
  }

  if (customSkin.skinTone) {
    skinTone = customSkin.skinTone;
  }

  sendJson(res, 200, {
    uuid,
    skinTone,
    bodyType,
    parts: resolvedParts,
    raw: customSkin
  });
}

// Handle customizer route
function handleCustomizerRoute(req, res, urlPath) {
  // Parse UUID from path: /customizer/{uuid} or just /customizer
  const pathParts = urlPath.split('/').filter(p => p);
  const uuid = pathParts[1] || 'preview';

  const customizerPath = path.join(__dirname, 'assets', 'customizer.html');

  if (fs.existsSync(customizerPath)) {
    let html = fs.readFileSync(customizerPath, 'utf8');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  } else {
    // Redirect to avatar viewer if customizer not found
    res.writeHead(302, { 'Location': `/avatar/${uuid}` });
    res.end();
  }
}

// Handle cosmetics list API - returns full cosmetic data with thumbnails
function handleCosmeticsList(req, res) {
  const configs = loadCosmeticConfigs();
  const gradientSets = loadGradientSets();

  if (!configs) {
    sendJson(res, 200, {});
    return;
  }

  // Build response with full item data including thumbnails
  const result = {};

  for (const [category, items] of Object.entries(configs)) {
    result[category] = [];
    for (const [id, item] of Object.entries(items)) {
      const itemData = {
        id: item.Id,
        name: item.Name || item.Id,
        thumbnail: item.GreyscaleTexture || item.Texture || null,
        gradientSet: item.GradientSet || null,
        model: item.Model || null
      };

      // Get available colors for this item
      if (item.GradientSet && gradientSets) {
        const gradientSetConfig = gradientSets.find(g => g.Id === item.GradientSet);
        if (gradientSetConfig && gradientSetConfig.Gradients) {
          itemData.colors = Object.keys(gradientSetConfig.Gradients);
        }
      } else if (item.Textures) {
        itemData.colors = Object.keys(item.Textures);
      }

      result[category].push(itemData);
    }
  }

  sendJson(res, 200, result);
}

// Handle single cosmetic item data request (for 3D thumbnail rendering)
// URL format: /cosmetics/item/{category}/{itemId} or /cosmetics/item/{category}/{itemId}/{colorId}
function handleCosmeticItem(req, res, urlPath) {
  const pathParts = urlPath.split('/').filter(p => p);
  // pathParts: ['cosmetics', 'item', category, itemId, colorId?]

  if (pathParts.length < 4) {
    sendJson(res, 400, { error: 'Category and item ID required' });
    return;
  }

  const category = pathParts[2];
  const itemId = pathParts[3];
  const colorId = pathParts[4] || null;

  // Build the item string (itemId or itemId.colorId)
  const itemString = colorId ? `${itemId}.${colorId}` : itemId;

  // Load configs
  const configs = loadCosmeticConfigs();
  const gradientSets = loadGradientSets();

  if (!configs) {
    sendJson(res, 500, { error: 'Could not load cosmetic configs' });
    return;
  }

  // Resolve the item
  const resolved = resolveSkinPart(category, itemString, configs, gradientSets);

  if (!resolved) {
    sendJson(res, 404, { error: 'Item not found', category, itemId });
    return;
  }

  sendJson(res, 200, {
    category,
    itemId,
    colorId,
    resolved
  });
}

// Handle static assets (avatar.js, etc.)
function handleStaticAssets(req, res, urlPath) {
  const assetPath = urlPath.replace('/assets/', '');
  const filePath = path.join(__dirname, 'assets', assetPath);

  if (!fs.existsSync(filePath)) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }

  // Determine content type
  let contentType = 'application/octet-stream';
  if (assetPath.endsWith('.js')) {
    contentType = 'application/javascript';
  } else if (assetPath.endsWith('.css')) {
    contentType = 'text/css';
  } else if (assetPath.endsWith('.html')) {
    contentType = 'text/html';
  } else if (assetPath.endsWith('.json')) {
    contentType = 'application/json';
  } else if (assetPath.endsWith('.png')) {
    contentType = 'image/png';
  } else if (assetPath.endsWith('.jpg') || assetPath.endsWith('.jpeg')) {
    contentType = 'image/jpeg';
  }

  const content = fs.readFileSync(filePath);
  res.writeHead(200, {
    'Content-Type': contentType,
    'Cache-Control': 'public, max-age=3600'
  });
  res.end(content);
}

// Handle asset extraction route
function handleAssetRoute(req, res, urlPath) {
  // Extract asset path from URL: /asset/path/to/asset.ext
  const assetPath = urlPath.replace('/asset/', '');

  if (!assetPath) {
    sendJson(res, 400, { error: 'Asset path required' });
    return;
  }

  const content = extractAsset(assetPath);

  if (!content) {
    res.writeHead(404);
    res.end('Asset not found');
    return;
  }

  // Determine content type
  let contentType = 'application/octet-stream';
  if (assetPath.endsWith('.json') || assetPath.endsWith('.blockymodel') || assetPath.endsWith('.blockyanim')) {
    contentType = 'application/json';
  } else if (assetPath.endsWith('.png')) {
    contentType = 'image/png';
  } else if (assetPath.endsWith('.jpg') || assetPath.endsWith('.jpeg')) {
    contentType = 'image/jpeg';
  }

  res.writeHead(200, {
    'Content-Type': contentType,
    'Cache-Control': 'public, max-age=86400'
  });
  res.end(content);
}

// Generate embedded avatar viewer HTML
function generateAvatarViewerHtml(uuid) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Avatar Viewer - ${uuid}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      color: #fff;
    }
    .container { display: flex; flex-direction: column; align-items: center; padding: 20px; }
    h1 { margin-bottom: 10px; font-size: 1.5rem; }
    .uuid { font-family: monospace; background: rgba(255,255,255,0.1); padding: 5px 10px; border-radius: 4px; font-size: 0.9rem; margin-bottom: 20px; }
    #canvas-container { width: 100%; max-width: 600px; aspect-ratio: 1; background: rgba(0,0,0,0.3); border-radius: 10px; overflow: hidden; position: relative; }
    #loading { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }
    .spinner { width: 40px; height: 40px; border: 3px solid rgba(255,255,255,0.2); border-top-color: #fff; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 10px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    #error { color: #ff6b6b; padding: 20px; text-align: center; display: none; }
    .controls { margin-top: 20px; display: flex; gap: 10px; flex-wrap: wrap; justify-content: center; }
    button { background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); color: #fff; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
    button:hover { background: rgba(255,255,255,0.2); }
    button.active { background: rgba(100,149,237,0.4); border-color: rgba(100,149,237,0.6); }
    .info { margin-top: 20px; background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; max-width: 600px; width: 100%; }
    .info h3 { margin-bottom: 10px; font-size: 1rem; }
    .parts-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 8px; font-size: 0.85rem; }
    .part-item { background: rgba(255,255,255,0.05); padding: 5px 10px; border-radius: 4px; }
    .part-name { color: #888; font-size: 0.75rem; }
    .status { position: absolute; bottom: 10px; left: 10px; font-size: 0.7rem; color: rgba(255,255,255,0.5); }
  </style>
</head>
<body>
  <div class="container" id="main-container">
    <h1>Hytale Avatar Viewer</h1>
    <div class="uuid">${uuid}</div>
    <div id="canvas-container">
      <div id="loading"><div class="spinner"></div><div id="loading-text">Loading avatar...</div></div>
      <div id="error"></div>
      <div class="status" id="status"></div>
    </div>
    <div class="controls">
      <button id="rotate-left">Rotate Left</button>
      <button id="rotate-right">Rotate Right</button>
      <button id="reset">Reset View</button>
      <button id="toggle-wireframe">Wireframe</button>
      <button id="toggle-autorotate" class="active">Auto-Rotate</button>
      <select id="animation-select" style="background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); color: #fff; padding: 10px; border-radius: 5px; cursor: pointer;">
        <option value="">No Animation</option>
        <option value="Default/Idle" selected>Idle</option>
        <option value="Default/Walk">Walk</option>
        <option value="Default/Run">Run</option>
        <option value="Default/Sprint">Sprint</option>
        <option value="Default/Jump">Jump</option>
        <option value="Default/Fall">Fall</option>
        <option value="Default/Crouch">Crouch</option>
        <option value="Emote/Wave">Wave</option>
        <option value="Emote/Dab_Left">Dab Left</option>
        <option value="Emote/Dab_Right">Dab Right</option>
        <option value="Taunt/Laugh">Laugh</option>
        <option value="Taunt/Chicken">Chicken</option>
        <option value="Taunt/Punch">Punch</option>
        <option value="Poses/Sword">Sword Pose</option>
        <option value="Poses/Staff">Staff Pose</option>
        <option value="Poses/Ninja">Ninja Pose</option>
        <option value="Climb/Climb_Idle">Climb Idle</option>
        <option value="Swim/Swim">Swim</option>
        <option value="Glide/Glide">Glide</option>
        <option value="Roll/Roll">Roll</option>
      </select>
    </div>
    <div class="info" id="skin-info" style="display: none;">
      <h3>Equipped Items</h3>
      <div class="parts-list" id="parts-list"></div>
    </div>
  </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
  <script>
    const UUID = '${uuid}';
    const SCALE = 0.01; // BlockyModel units to world units

    let scene, camera, renderer, character, rotationSpeed = 0;
    let modelData = null;
    let wireframeMode = false;
    let autoRotate = true;

    // Animation state
    let currentAnimation = null;
    let animationTime = 0;
    let lastFrameTime = 0;
    let animationEnabled = true;
    let currentAnimationPath = 'Default/Idle';
    const FPS = 60; // Hytale animations run at 60fps

    // Texture cache
    const textureCache = new Map();
    const textureLoader = new THREE.TextureLoader();

    // Body parts that should be hidden when clothing is equipped
    const hiddenBodyParts = new Set();
    // Body parts that should use polygon offset (pushed back in depth buffer)
    // so clothing can render in front without z-fighting
    const polygonOffsetParts = new Set();

    // Load animation by path
    async function loadAnimation(animPath) {
      if (!animPath) return null;
      try {
        const response = await fetch('/asset/Common/Characters/Animations/' + animPath + '.blockyanim');
        if (!response.ok) return null;
        return await response.json();
      } catch (e) {
        console.error('[ANIMATION] Failed to load animation:', animPath, e);
        return null;
      }
    }

    // Reset character to original pose (before animation)
    function resetToOriginalPose() {
      originalTransforms.forEach((transform, nodeName) => {
        const node = character?.getObjectByName(nodeName);
        if (node) {
          node.position.copy(transform.position);
          node.quaternion.copy(transform.quaternion);
        }
      });
    }

    // Change animation
    async function changeAnimation(animPath) {
      currentAnimationPath = animPath;
      animationTime = 0;

      if (!animPath) {
        currentAnimation = null;
        resetToOriginalPose();
        return;
      }

      currentAnimation = await loadAnimation(animPath);
      if (!currentAnimation) {
        console.warn('[ANIMATION] Could not load:', animPath);
      }
    }

    // Catmull-Rom interpolation for smooth keyframes
    function catmullRomInterpolate(p0, p1, p2, p3, t) {
      const t2 = t * t;
      const t3 = t2 * t;
      return 0.5 * (
        (2 * p1) +
        (-p0 + p2) * t +
        (2 * p0 - 5 * p1 + 4 * p2 - p3) * t2 +
        (-p0 + 3 * p1 - 3 * p2 + p3) * t3
      );
    }

    // Find keyframes surrounding the current time for looping animation
    function findKeyframes(keyframes, time, duration) {
      if (!keyframes || keyframes.length === 0) return null;
      if (keyframes.length === 1) {
        return { k1: keyframes[0], k2: keyframes[0], t: 0 };
      }

      // Sort keyframes by time (should already be sorted, but just in case)
      const sorted = [...keyframes].sort((a, b) => a.time - b.time);

      // Find the two keyframes we're between
      let idx1 = -1;
      for (let i = 0; i < sorted.length; i++) {
        if (sorted[i].time <= time) {
          idx1 = i;
        } else {
          break;
        }
      }

      // If time is before first keyframe, interpolate from last to first
      if (idx1 === -1) {
        const k1 = sorted[sorted.length - 1];
        const k2 = sorted[0];
        // Time from last keyframe (wrapping through 0)
        const t1 = k1.time;
        const t2 = k2.time + duration;
        const currentTime = time + duration;
        let t = (t2 - t1) > 0 ? (currentTime - t1) / (t2 - t1) : 0;
        t = Math.max(0, Math.min(1, t));
        return { k1, k2, t, smooth: k1.interpolationType === 'smooth' };
      }

      // If at or after last keyframe, interpolate to first keyframe (loop)
      if (idx1 === sorted.length - 1) {
        const k1 = sorted[idx1];
        const k2 = sorted[0];
        // Time from last keyframe to first (wrapping)
        const timeSpan = (duration - k1.time) + k2.time;
        const elapsed = time - k1.time;
        let t = timeSpan > 0 ? elapsed / timeSpan : 0;
        t = Math.max(0, Math.min(1, t));
        return { k1, k2, t, smooth: k1.interpolationType === 'smooth' };
      }

      // Normal case: between two keyframes
      const k1 = sorted[idx1];
      const k2 = sorted[idx1 + 1];
      const timeSpan = k2.time - k1.time;
      let t = timeSpan > 0 ? (time - k1.time) / timeSpan : 0;
      t = Math.max(0, Math.min(1, t));
      return { k1, k2, t, smooth: k1.interpolationType === 'smooth' };
    }

    // Interpolate quaternion keyframes
    function interpolateQuaternion(keyframes, time, duration) {
      const kf = findKeyframes(keyframes, time, duration);
      if (!kf) return null;

      const { k1, k2, smooth } = kf;
      let t = kf.t;

      const q1 = new THREE.Quaternion(k1.delta.x, k1.delta.y, k1.delta.z, k1.delta.w);
      const q2 = new THREE.Quaternion(k2.delta.x, k2.delta.y, k2.delta.z, k2.delta.w);

      // Apply smoothstep easing for smooth interpolation
      if (smooth) {
        t = t * t * (3 - 2 * t);
      }

      const result = new THREE.Quaternion();
      result.slerpQuaternions(q1, q2, t);
      return result;
    }

    // Interpolate position keyframes
    function interpolatePosition(keyframes, time, duration) {
      const kf = findKeyframes(keyframes, time, duration);
      if (!kf) return null;

      const { k1, k2, smooth } = kf;
      let t = kf.t;

      // Apply smoothstep easing for smooth interpolation
      if (smooth) {
        t = t * t * (3 - 2 * t);
      }

      const v1 = new THREE.Vector3(k1.delta.x, k1.delta.y, k1.delta.z);
      const v2 = new THREE.Vector3(k2.delta.x, k2.delta.y, k2.delta.z);
      const result = new THREE.Vector3();
      result.lerpVectors(v1, v2, t);
      result.multiplyScalar(SCALE);
      return result;
    }

    // Store original transforms for animation blending
    const originalTransforms = new Map();

    // Apply animation to character
    function applyAnimation(animation, time) {
      if (!animation || !animation.nodeAnimations || !character) return;

      const duration = animation.duration;
      // Use modulo for looping, but keep it smooth by using floating point
      const loopTime = ((time % duration) + duration) % duration;

      for (const [nodeName, nodeAnim] of Object.entries(animation.nodeAnimations)) {
        const node = character.getObjectByName(nodeName);
        if (!node) {
          // Only log once per missing bone
          if (!applyAnimation.missingBones) applyAnimation.missingBones = new Set();
          if (!applyAnimation.missingBones.has(nodeName)) {
            console.warn('[ANIMATION] Bone not found:', nodeName);
            applyAnimation.missingBones.add(nodeName);
          }
          continue;
        }

        // Store original transform on first use
        if (!originalTransforms.has(nodeName)) {
          originalTransforms.set(nodeName, {
            position: node.position.clone(),
            quaternion: node.quaternion.clone()
          });
        }
        const original = originalTransforms.get(nodeName);

        // Apply orientation (quaternion) animation
        if (nodeAnim.orientation && nodeAnim.orientation.length > 0) {
          const animQuat = interpolateQuaternion(nodeAnim.orientation, loopTime, duration);
          if (animQuat) {
            // Animation delta is applied on top of original orientation
            node.quaternion.copy(original.quaternion);
            node.quaternion.multiply(animQuat);
          }
        }

        // Apply position animation
        if (nodeAnim.position && nodeAnim.position.length > 0) {
          const animPos = interpolatePosition(nodeAnim.position, loopTime, duration);
          if (animPos) {
            // Animation delta is added to original position
            node.position.copy(original.position);
            node.position.add(animPos);
          }
        }
      }
    }

    async function init() {
      try {
        setLoadingText('Fetching skin data...');
        const response = await fetch('/avatar/' + UUID + '/model');
        if (!response.ok) throw new Error('Failed to load avatar data');
        modelData = await response.json();
        if (modelData.error) throw new Error(modelData.error);

        displaySkinInfo(modelData);
        initThreeJS();

        // Determine which body parts to hide based on equipped cosmetics
        determineHiddenParts(modelData);

        setLoadingText('Building character...');
        await buildCharacter(modelData);

        // Load default animation
        setLoadingText('Loading animation...');
        currentAnimation = await loadAnimation(currentAnimationPath);
        if (currentAnimation) {
          console.log('[ANIMATION] Loaded animation:', currentAnimationPath, 'duration:', currentAnimation.duration, 'frames');
        }

        // Setup animation selector
        document.getElementById('animation-select').addEventListener('change', async function(e) {
          await changeAnimation(e.target.value);
        });

        document.getElementById('loading').style.display = 'none';
        updateStatus('Ready - Drag to rotate');
        lastFrameTime = performance.now();
        animate();
      } catch (err) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('error').style.display = 'block';
        document.getElementById('error').textContent = err.message;
        console.error('Error:', err);
      }
    }

    function setLoadingText(text) { document.getElementById('loading-text').textContent = text; }
    function updateStatus(text) { document.getElementById('status').textContent = text; }

    function displaySkinInfo(data) {
      const infoEl = document.getElementById('skin-info');
      const listEl = document.getElementById('parts-list');
      if (!data.parts || Object.keys(data.parts).length === 0) return;
      infoEl.style.display = 'block';
      listEl.innerHTML = '';
      for (const [category, part] of Object.entries(data.parts)) {
        const item = document.createElement('div');
        item.className = 'part-item';
        item.innerHTML = '<div class="part-name">' + category + '</div><div>' + (part.id || category) + (part.colorId ? '.' + part.colorId : '') + '</div>';
        listEl.appendChild(item);
      }
    }

    function determineHiddenParts(data) {
      // Hide body parts covered by clothing
      if (data.parts?.pants || data.parts?.overpants) {
        hiddenBodyParts.add('Pelvis');
        hiddenBodyParts.add('L-Thigh');
        hiddenBodyParts.add('R-Thigh');
        hiddenBodyParts.add('L-Calf');
        hiddenBodyParts.add('R-Calf');
      }
      // Don't hide arms - use polygon offset instead to let clothing cover body naturally
      // Only hide torso parts that are always fully covered
      if (data.parts?.overtop || data.parts?.undertop) {
        hiddenBodyParts.add('Belly');
        hiddenBodyParts.add('Chest');
        // Keep arms visible but push them back in depth buffer
        // so clothing sleeves render in front
        polygonOffsetParts.add('L-Arm');
        polygonOffsetParts.add('R-Arm');
        polygonOffsetParts.add('L-Forearm');
        polygonOffsetParts.add('R-Forearm');
      }
      if (data.parts?.shoes) {
        hiddenBodyParts.add('L-Foot');
        hiddenBodyParts.add('R-Foot');
      }
      // Don't hide hands for gloves - most glove models are accessories (bracelets, etc)
      // that render on top of hands, not full hand replacements
      // if (data.parts?.gloves) {
      //   hiddenBodyParts.add('L-Hand');
      //   hiddenBodyParts.add('R-Hand');
      // }
      // Hide head parts when hair/accessories equipped (but keep face visible)
      if (data.parts?.haircut) {
        hiddenBodyParts.add('HeadTop');
        hiddenBodyParts.add('HairBase');
      }
      console.log('[AVATAR] Hidden body parts:', Array.from(hiddenBodyParts));
      console.log('[AVATAR] Polygon offset parts:', Array.from(polygonOffsetParts));
    }

    function initThreeJS() {
      const container = document.getElementById('canvas-container');
      const width = container.clientWidth;
      const height = container.clientHeight;

      scene = new THREE.Scene();
      scene.background = new THREE.Color(0x1a1a2e);

      camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
      camera.position.set(0, 0.6, 2.0);
      camera.lookAt(0, 0.5, 0);

      renderer = new THREE.WebGLRenderer({ antialias: true });
      renderer.setSize(width, height);
      renderer.setPixelRatio(window.devicePixelRatio);
      container.appendChild(renderer.domElement);

      // Better lighting
      scene.add(new THREE.AmbientLight(0xffffff, 0.7));
      const dirLight = new THREE.DirectionalLight(0xffffff, 0.6);
      dirLight.position.set(2, 3, 2);
      scene.add(dirLight);
      const backLight = new THREE.DirectionalLight(0xffffff, 0.3);
      backLight.position.set(-2, 1, -2);
      scene.add(backLight);
      const fillLight = new THREE.DirectionalLight(0xffffff, 0.2);
      fillLight.position.set(0, -1, 2);
      scene.add(fillLight);

      scene.add(new THREE.GridHelper(2, 10, 0x444444, 0x333333));

      character = new THREE.Group();
      // Rotate character to face camera
      // Hytale character faces +Z, camera is at +Z looking at origin
      // So rotate 180° around Y to face the camera
      character.rotation.y = Math.PI;
      scene.add(character);

      window.addEventListener('resize', () => {
        const w = container.clientWidth, h = container.clientHeight;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
      });

      let isDragging = false, prevX = 0;
      container.addEventListener('mousedown', (e) => { isDragging = true; prevX = e.clientX; autoRotate = false; document.getElementById('toggle-autorotate').classList.remove('active'); });
      window.addEventListener('mouseup', () => isDragging = false);
      window.addEventListener('mousemove', (e) => { if (isDragging) { character.rotation.y += (e.clientX - prevX) * 0.01; prevX = e.clientX; } });
      container.addEventListener('touchstart', (e) => { isDragging = true; prevX = e.touches[0].clientX; autoRotate = false; document.getElementById('toggle-autorotate').classList.remove('active'); });
      container.addEventListener('touchend', () => isDragging = false);
      container.addEventListener('touchmove', (e) => { if (isDragging) { character.rotation.y += (e.touches[0].clientX - prevX) * 0.01; prevX = e.touches[0].clientX; } });

      document.getElementById('rotate-left').onclick = () => { rotationSpeed = -0.05; setTimeout(() => rotationSpeed = 0, 300); };
      document.getElementById('rotate-right').onclick = () => { rotationSpeed = 0.05; setTimeout(() => rotationSpeed = 0, 300); };
      document.getElementById('reset').onclick = () => character.rotation.y = Math.PI; // Face camera (default view)
      document.getElementById('toggle-wireframe').onclick = (e) => {
        wireframeMode = !wireframeMode;
        e.target.classList.toggle('active', wireframeMode);
        character.traverse((c) => { if (c.isMesh) c.material.wireframe = wireframeMode; });
      };
      document.getElementById('toggle-autorotate').onclick = (e) => {
        autoRotate = !autoRotate;
        e.target.classList.toggle('active', autoRotate);
      };
    }

    // Load texture with caching
    async function loadTexture(path) {
      if (textureCache.has(path)) return textureCache.get(path);

      return new Promise((resolve) => {
        const fullPath = path.startsWith('Common/') ? '/asset/' + path : '/asset/Common/' + path;
        textureLoader.load(fullPath,
          (texture) => {
            texture.magFilter = THREE.NearestFilter;
            texture.minFilter = THREE.NearestFilter;
            texture.wrapS = THREE.ClampToEdgeWrapping;
            texture.wrapT = THREE.ClampToEdgeWrapping;
            texture.generateMipmaps = false;
            textureCache.set(path, texture);
            resolve(texture);
          },
          undefined,
          (err) => {
            const altPath = '/asset/' + path.replace('Common/', '');
            textureLoader.load(altPath,
              (texture) => {
                texture.magFilter = THREE.NearestFilter;
                texture.minFilter = THREE.NearestFilter;
                texture.wrapS = THREE.ClampToEdgeWrapping;
                texture.wrapT = THREE.ClampToEdgeWrapping;
                texture.generateMipmaps = false;
                textureCache.set(path, texture);
                resolve(texture);
              },
              undefined,
              () => resolve(null)
            );
          }
        );
      });
    }

    // Helper to load gradient data
    async function loadGradientData(gradientTexturePath) {
      if (!gradientTexturePath) return null;
      try {
        const gradientTexture = await loadTexture(gradientTexturePath);
        if (gradientTexture && gradientTexture.image) {
          const gradCanvas = document.createElement('canvas');
          gradCanvas.width = gradientTexture.image.width;
          gradCanvas.height = gradientTexture.image.height;
          const gradCtx = gradCanvas.getContext('2d');
          gradCtx.drawImage(gradientTexture.image, 0, 0);
          return gradCtx.getImageData(0, 0, gradCanvas.width, gradCanvas.height);
        }
      } catch (e) {
        console.error('[TINT] Gradient load error:', gradientTexturePath, e);
      }
      return null;
    }

    // Helper to create final texture from canvas
    function createCanvasTexture(canvas) {
      const tintedTexture = new THREE.CanvasTexture(canvas);
      tintedTexture.magFilter = THREE.NearestFilter;
      tintedTexture.minFilter = THREE.NearestFilter;
      tintedTexture.wrapS = THREE.ClampToEdgeWrapping;
      tintedTexture.wrapT = THREE.ClampToEdgeWrapping;
      tintedTexture.generateMipmaps = false;
      tintedTexture.userData = { width: canvas.width, height: canvas.height };
      return tintedTexture;
    }

    /**
     * Hytale-accurate greyscale tinting
     *
     * From BlockyModelFS.glsl:
     *   bool isGreyscale = (texel.r == texel.g) && (texel.g == texel.b);
     *   if(gradientId > 0 && isGreyscale) {
     *     ivec2 coord = ivec2(texel.r * 255, gradientId - 1);
     *     vec3 finalColor = texelFetch(uGradientAtlasTexture, coord, 0).rgb;
     *     outColor0.rgb = finalColor.rgb;
     *   }
     *
     * Rules:
     * 1. ONLY pixels where R == G == B (exactly) are tinted
     * 2. Colored pixels (R != G or G != B) keep their original color
     * 3. The greyscale value (0-255) is used as X coordinate in gradient texture
     */
    async function createTintedTexture(greyscalePath, baseColor, gradientTexturePath = null) {
      const texture = await loadTexture(greyscalePath);
      if (!texture || !texture.image) return null;

      const canvas = document.createElement('canvas');
      const img = texture.image;
      canvas.width = img.width;
      canvas.height = img.height;

      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const data = imageData.data;
      const gradientData = await loadGradientData(gradientTexturePath);
      const color = parseColor(baseColor);

      for (let i = 0; i < data.length; i += 4) {
        const origR = data[i];
        const origG = data[i + 1];
        const origB = data[i + 2];
        const alpha = data[i + 3];

        if (alpha > 0) {
          // Hytale shader: isGreyscale = (texel.r == texel.g) && (texel.g == texel.b)
          // STRICT equality check - only tint true greyscale pixels
          const isGreyscale = (origR === origG) && (origG === origB);

          if (isGreyscale) {
            // Apply gradient tinting using R value as index
            const grey = origR;
            let r, g, b;

            if (gradientData) {
              // Gradient texture lookup: X = greyscale value (0-255)
              const gradX = Math.min(grey, gradientData.width - 1);
              const gradIdx = gradX * 4;
              r = gradientData.data[gradIdx];
              g = gradientData.data[gradIdx + 1];
              b = gradientData.data[gradIdx + 2];
            } else if (color) {
              // Fallback: multiply base color by greyscale intensity
              const t = grey / 255;
              r = Math.round(Math.min(255, color.r * t * 2));
              g = Math.round(Math.min(255, color.g * t * 2));
              b = Math.round(Math.min(255, color.b * t * 2));
            } else {
              // No gradient and no base color - keep as greyscale
              r = grey;
              g = grey;
              b = grey;
            }

            data[i] = r;
            data[i + 1] = g;
            data[i + 2] = b;
          }
          // Non-greyscale pixels (colored): keep original color unchanged
          // This includes fur (blue-tinted), leather (brown), gold buttons, stripes, etc.
        }
      }

      ctx.putImageData(imageData, 0, 0);
      return createCanvasTexture(canvas);
    }

    // Aliases for backward compatibility - all use the same Hytale-accurate tinting
    const createSimpleTintedTexture = createTintedTexture;
    const createCosmeticTintedTexture = createTintedTexture;

    // Create eye shadow texture - converts white eye background to transparent shadow gradient
    // Dark at edges (shadow), fading to transparent in center (where pupil goes)
    async function createEyeShadowTexture(originalTexture) {
      if (!originalTexture || !originalTexture.image) return null;

      const img = originalTexture.image;
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');

      // Draw original
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, img.width, img.height);
      const data = imageData.data;

      // Process: convert white areas to shadow gradient
      // Center of each eye region: (1+7, 1+7) = (8, 8) for right eye bg
      const regions = [
        { cx: 8, cy: 8 },   // Right eye background (offset 1,1, size 14x14)
        { cx: 24, cy: 8 },  // Left eye background (offset 17,1, size 14x14) - if exists
      ];

      for (let y = 0; y < img.height; y++) {
        for (let x = 0; x < img.width; x++) {
          const idx = (y * img.width + x) * 4;
          const r = data[idx];
          const g = data[idx + 1];
          const b = data[idx + 2];
          const a = data[idx + 3];

          // Only process opaque/semi-opaque pixels in the background region (top half)
          if (y < 16 && a > 0) {
            // Determine which eye region this pixel is in
            let localX = -1, localY = -1;
            // Right eye: offset (1,1), size 14x14
            if (x >= 1 && x < 15 && y >= 1 && y < 15) {
              localX = x - 1; // 0-13 within eye region
              localY = y - 1;
            }
            // Left eye: offset (17,1) or similar
            else if (x >= 17 && x < 31 && y >= 1 && y < 15) {
              localX = x - 17;
              localY = y - 1;
            }

            if (localX >= 0 && localY >= 0) {
              // Soft eyelid shadow - very subtle, only at the very top
              const eyeSize = 14;

              // Only shadow in top 4 pixels, fade quickly
              let shadowAlpha = 0;
              if (localY < 4) {
                shadowAlpha = (1 - localY / 4) * 0.25; // max 25% at very top, fades to 0 by row 4
              }

              data[idx] = 0;     // R - black shadow
              data[idx + 1] = 0; // G
              data[idx + 2] = 0; // B
              data[idx + 3] = Math.round(shadowAlpha * 255 * (a / 255));
            } else {
              // Outside eye regions - make transparent
              data[idx + 3] = 0;
            }
          }
        }
      }

      ctx.putImageData(imageData, 0, 0);
      return createCanvasTexture(canvas);
    }

    function parseColor(color) {
      if (typeof color === 'number') {
        return {
          r: (color >> 16) & 255,
          g: (color >> 8) & 255,
          b: color & 255
        };
      }
      if (typeof color === 'string') {
        if (color.startsWith('#')) {
          const hex = color.slice(1);
          return {
            r: parseInt(hex.substr(0, 2), 16),
            g: parseInt(hex.substr(2, 2), 16),
            b: parseInt(hex.substr(4, 2), 16)
          };
        }
      }
      if (Array.isArray(color)) {
        return parseColor(color[0]);
      }
      return { r: 200, g: 200, b: 200 };
    }

    async function buildCharacter(data) {
      console.log('[AVATAR] Building character...');
      console.log('[AVATAR] Skin data:', JSON.stringify(data, null, 2));

      const skinColor = getSkinToneColor(data.skinTone);
      const skinColorHex = '#' + skinColor.toString(16).padStart(6, '0');
      const skinToneGradient = getSkinToneGradientPath(data.skinTone);
      console.log('[AVATAR] Skin tone:', data.skinTone, 'color:', skinColorHex, 'gradient:', skinToneGradient);

      // Load base player model
      setLoadingText('Loading player model...');
      try {
        const playerModel = await fetchModel('Common/Characters/Player.blockymodel');
        if (playerModel) {
          const bodyTexturePath = data.bodyType === 'Muscular'
            ? 'Characters/Player_Textures/Player_Muscular_Greyscale.png'
            : 'Characters/Player_Textures/Player_Greyscale.png';

          let bodyTexture = null;
          try {
            console.log('[AVATAR] Loading body texture:', bodyTexturePath);
            console.log('[AVATAR] Tinting with skin color:', skinColorHex, 'gradient:', skinToneGradient);
            bodyTexture = await createTintedTexture(bodyTexturePath, skinColorHex, skinToneGradient);
            console.log('[AVATAR] Body texture created:', bodyTexture ? 'success' : 'null');
          } catch (e) {
            console.error('[AVATAR] Failed to load player body texture:', e);
          }

          await renderPlayerModel(playerModel.nodes, character, skinColor, bodyTexture);
        }
      } catch (e) {
        console.error('[AVATAR] Could not load player model:', e);
      }

      // Cosmetics render order (later = on top)
      const cosmeticOrder = [
        { key: 'underwear', zOffset: 0 },
        { key: 'pants', zOffset: 0.001 },
        { key: 'overpants', zOffset: 0.002 },
        { key: 'shoes', zOffset: 0.001 },
        { key: 'undertop', zOffset: 0.001 },
        { key: 'overtop', zOffset: 0.002 },
        { key: 'gloves', zOffset: 0.001 },
        { key: 'face', zOffset: 0.01 },
        { key: 'mouth', zOffset: 0.015 },
        { key: 'eyes', zOffset: 0.02 },  // In front of face
        { key: 'eyebrows', zOffset: 0.025 },
        { key: 'ears', zOffset: 0 },
        { key: 'haircut', zOffset: 0.005 },
        { key: 'facialHair', zOffset: 0.004 },
        { key: 'headAccessory', zOffset: 0.006 },
        { key: 'faceAccessory', zOffset: 0.005 },
        { key: 'earAccessory', zOffset: 0.001 },
        { key: 'cape', zOffset: -0.001 }
      ];

      for (const { key, zOffset } of cosmeticOrder) {
        const part = data.parts?.[key];
        if (part && part.model) {
          console.log('[COSMETIC]', key, '- model:', part.model);
          setLoadingText('Loading ' + key + '...');

          // Get color for this part
          let color = getPartColor(part);
          if (!color) {
            if (['face', 'ears'].includes(key)) {
              color = skinColor;
            } else {
              color = getDefaultColor(key, skinColor);
            }
          }

          // Determine texture to use
          // Hytale uses strict R==G==B check for greyscale - colored pixels stay unchanged
          let texture = null;

          // Skin parts use skin gradient
          const isSkinPart = part.gradientSet === 'Skin' || ['face', 'ears', 'mouth'].includes(key);

          if (part.texture) {
            // Direct texture - no tinting needed (pre-colored texture)
            try {
              console.log('[COSMETIC]', key, '- loading direct texture:', part.texture);
              texture = await loadTexture(part.texture);
            } catch (e) { console.error('[COSMETIC]', key, '- texture error:', e); }
          } else if (part.greyscaleTexture) {
            // Greyscale texture - apply Hytale-accurate tinting
            // Only pixels where R==G==B are tinted, colored pixels stay unchanged
            try {
              let gradientPath = part.gradientTexture;
              let baseCol = part.baseColor;

              // Skin parts use skin gradient
              if (isSkinPart) {
                gradientPath = skinToneGradient;
                baseCol = skinColorHex;
                color = skinColor;
              }

              // If no color specified, use default color for this part type
              if (!gradientPath && !baseCol) {
                baseCol = '#' + getDefaultColor(key, skinColor).toString(16).padStart(6, '0');
              }

              console.log('[COSMETIC]', key, '- tinting (Hytale-style R==G==B)', gradientPath ? 'with gradient' : 'with color:', baseCol);
              texture = await createTintedTexture(part.greyscaleTexture, baseCol, gradientPath);
            } catch (e) { console.error('[COSMETIC]', key, '- tint error:', e); }
          }

          try {
            let modelPath = part.model;
            if (!modelPath.startsWith('Common/')) modelPath = 'Common/' + modelPath;
            const model = await fetchModel(modelPath);
            if (model) {
              console.log('[COSMETIC]', key, '- loaded, rendering', model.nodes?.length, 'nodes, texture:', texture ? 'yes' : 'no');

              // For eyes, create shadow texture for background
              let shadowTexture = null;
              if (key === 'eyes' && texture) {
                shadowTexture = await createEyeShadowTexture(texture);
              }

              await renderCosmeticModel(model.nodes, character, color, key, texture, zOffset, shadowTexture);
            } else {
              console.error('[COSMETIC]', key, '- model is null for:', modelPath);
            }
          } catch (e) {
            console.error('[COSMETIC]', key, '- error:', e);
          }
        } else if (part) {
          console.log('[COSMETIC]', key, '- skipped (no model):', part);
        }
      }
      console.log('[AVATAR] Character built successfully');
    }

    async function fetchModel(path) {
      const response = await fetch('/asset/' + path);
      if (!response.ok) return null;
      return response.json();
    }

    // Render player body model with skin tone and texture
    async function renderPlayerModel(nodes, parent, skinColor, bodyTexture) {
      if (!nodes) return;
      for (const node of nodes) {
        renderPlayerNode(node, parent, skinColor, bodyTexture, 0);
      }
    }

    function renderPlayerNode(node, parent, skinColor, bodyTexture, depth = 0) {
      const nodeName = node.name || node.id || '';

      // Debug: log when rendering Neck
      if (nodeName === 'Neck') {
        console.log('[DEBUG] Rendering Neck node:', JSON.stringify(node.shape));
        console.log('[DEBUG] Neck has texture:', !!bodyTexture);
      }

      // Skip hidden body parts (but still create group for hierarchy so cosmetics can attach)
      if (hiddenBodyParts.has(nodeName)) {
        const group = new THREE.Group();
        group.name = nodeName;
        applyTransform(group, node);
        parent.add(group);
        if (node.children) {
          for (const child of node.children) {
            renderPlayerNode(child, group, skinColor, bodyTexture, depth + 1);
          }
        }
        return;
      }

      const group = new THREE.Group();
      group.name = nodeName;
      applyTransform(group, node);

      // Create mesh at group origin (offset already included in group position)
      // Use polygon offset for body parts that should render behind clothing
      const usePolygonOffset = polygonOffsetParts.has(nodeName);
      if (node.shape && node.shape.visible !== false && node.shape.type === 'box') {
        const mesh = createBoxMesh(node.shape, skinColor, nodeName, bodyTexture, usePolygonOffset);
        if (mesh) group.add(mesh);
      } else if (node.shape && node.shape.type === 'quad') {
        const mesh = createQuadMesh(node.shape, skinColor, nodeName, bodyTexture);
        if (mesh) group.add(mesh);
      }

      parent.add(group);

      if (node.children) {
        for (const child of node.children) {
          renderPlayerNode(child, group, skinColor, bodyTexture, depth + 1);
        }
      }
    }

    // Render cosmetic model - matches cosmetic bone hierarchy to player bones
    async function renderCosmeticModel(nodes, parent, color, partType, texture, zOffset, shadowTexture = null) {
      if (!nodes) return;
      for (const node of nodes) {
        renderCosmeticNode(node, parent, color, partType, texture, zOffset, 0, shadowTexture);
      }
    }

    // Find a bone by name in the player hierarchy
    function findBoneByName(parent, name) {
      if (!name) return null;

      // Search in the character group
      let found = null;
      parent.traverse((obj) => {
        if (obj.name === name && !found) {
          found = obj;
        }
      });
      return found;
    }

    function renderCosmeticNode(node, parent, color, partType, texture, zOffset, depth = 0, shadowTexture = null) {
      const nodeName = node.name || node.id || '';

      // Try to find matching bone in player skeleton
      let targetParent = parent;
      let attachedToPlayerBone = false;
      if (nodeName) {
        const matchingBone = findBoneByName(character, nodeName);
        if (matchingBone) {
          targetParent = matchingBone;
          attachedToPlayerBone = true;
        }
      }

      const group = new THREE.Group();
      group.name = nodeName + '_cosmetic';

      // When attached to player bone: player bone provides position
      // Don't apply cosmetic's position/offset - it's for cosmetic's own coordinate system
      // When not attached: apply full transform (position + rotation + offset)
      if (attachedToPlayerBone) {
        // Only apply rotation
        if (node.orientation) {
          group.quaternion.set(
            node.orientation.x || 0,
            node.orientation.y || 0,
            node.orientation.z || 0,
            node.orientation.w || 1
          );
        }
      } else {
        applyTransform(group, node);
      }

      // Apply z-offset for layering at group level
      if (zOffset) {
        group.position.z += zOffset;
      }

      // Create mesh at group origin (offset already included in group position)
      if (node.shape && node.shape.visible !== false && node.shape.type !== 'none') {
        let mesh = null;
        if (node.shape.type === 'box') {
          mesh = createBoxMesh(node.shape, color, nodeName, texture);
        } else if (node.shape.type === 'quad') {
          // For eye background, use shadow texture instead of regular texture
          if (partType === 'eyes' && nodeName.includes('Background') && shadowTexture) {
            mesh = createQuadMesh(node.shape, color, nodeName, shadowTexture);
            // Shadow renders behind pupil with transparency
            mesh.renderOrder = 100;
            mesh.material.transparent = true;
            mesh.material.depthWrite = false;
            mesh.material.alphaTest = 0;
            mesh.material.blending = THREE.NormalBlending;
          } else {
            mesh = createQuadMesh(node.shape, color, nodeName, texture);

            // Eye pupil layering
            if (mesh && partType === 'eyes' && nodeName.includes('Eye') && !nodeName.includes('Attachment') && !nodeName.includes('Background')) {
              mesh.renderOrder = 101;
            }
          }

          if (mesh && partType === 'mouth') {
            mesh.renderOrder = 99;
          } else if (mesh && partType === 'face') {
            mesh.renderOrder = 98;
          }
        }
        if (mesh) group.add(mesh);
      }

      targetParent.add(group);

      // Process children
      if (node.children) {
        for (const child of node.children) {
          const childName = child.name || child.id || '';
          const childBone = findBoneByName(character, childName);
          if (childBone) {
            renderCosmeticNode(child, childBone, color, partType, texture, zOffset, depth + 1, shadowTexture);
          } else {
            // No matching bone, add as child of current group
            renderCosmeticNode(child, group, color, partType, texture, 0, depth + 1, shadowTexture);
          }
        }
      }
    }

    function applyTransform(group, node) {
      // Set orientation first (needed for offset transformation)
      if (node.orientation) {
        group.quaternion.set(
          node.orientation.x || 0,
          node.orientation.y || 0,
          node.orientation.z || 0,
          node.orientation.w || 1
        );
      }

      // Set position = node.position + transformed(offset)
      // This follows Hytale pattern: reference.Position += Vector3.Transform(node.Offset, reference.Orientation)
      let posX = (node.position?.x || 0) * SCALE;
      let posY = (node.position?.y || 0) * SCALE;
      let posZ = (node.position?.z || 0) * SCALE;

      if (node.shape && node.shape.offset) {
        const offset = new THREE.Vector3(
          (node.shape.offset.x || 0) * SCALE,
          (node.shape.offset.y || 0) * SCALE,
          (node.shape.offset.z || 0) * SCALE
        );
        offset.applyQuaternion(group.quaternion);
        posX += offset.x;
        posY += offset.y;
        posZ += offset.z;
      }

      group.position.set(posX, posY, posZ);
    }

    // Simple working box mesh - don't overcomplicate with Hytale source matching
    // usePolygonOffset: push body parts back in depth buffer so clothing renders in front
    function createBoxMesh(shape, color, nodeName, texture = null, usePolygonOffset = false) {
      const settings = shape.settings;
      if (!settings || !settings.size) {
        if (nodeName === 'Neck') console.log('[DEBUG] Neck: no settings or size!');
        return null;
      }
      if (nodeName === 'Neck') console.log('[DEBUG] Neck createBoxMesh called, size:', settings.size);

      const stretch = shape.stretch || { x: 1, y: 1, z: 1 };
      const sx = Math.abs(stretch.x || 1);
      const sy = Math.abs(stretch.y || 1);
      const sz = Math.abs(stretch.z || 1);

      // Handle negative stretch by flipping
      const flipX = (stretch.x || 1) < 0;
      const flipY = (stretch.y || 1) < 0;
      const flipZ = (stretch.z || 1) < 0;

      // Size in world units
      const width = settings.size.x * sx * SCALE;
      const height = settings.size.y * sy * SCALE;
      const depth = settings.size.z * sz * SCALE;

      // Size in pixels (for UV calculation)
      const pixelW = settings.size.x;
      const pixelH = settings.size.y;
      const pixelD = settings.size.z;

      const hasTextureLayout = texture && shape.textureLayout && Object.keys(shape.textureLayout).length > 0;
      const geometry = new THREE.BoxGeometry(width, height, depth);

      if (nodeName === 'Neck') {
        console.log('[DEBUG] Neck hasTextureLayout:', hasTextureLayout);
        console.log('[DEBUG] Neck textureLayout:', JSON.stringify(shape.textureLayout));
        console.log('[DEBUG] Neck dimensions (world):', width, height, depth);
        console.log('[DEBUG] Neck pixel sizes:', pixelW, pixelH, pixelD);
        if (texture) {
          console.log('[DEBUG] Neck texture size:', texture.image?.width, texture.image?.height, texture.userData);
        }
      }

      // Apply per-face UV mapping if texture and textureLayout exist
      if (hasTextureLayout) {
        const texW = texture.image?.width || texture.userData?.width;
        const texH = texture.image?.height || texture.userData?.height;

        if (texW && texH) {
          // Three.js BoxGeometry face order: +X, -X, +Y, -Y, +Z, -Z
          // Standard mapping: right, left, top, bottom, front, back
          const faceMap = ['right', 'left', 'top', 'bottom', 'front', 'back'];

          const uvAttr = geometry.getAttribute('uv');
          const uvArray = uvAttr.array;

          for (let faceIdx = 0; faceIdx < 6; faceIdx++) {
            const faceName = faceMap[faceIdx];
            const layout = shape.textureLayout[faceName];

            if (layout && layout.offset) {
              // Match Blockbench Hytale plugin UV calculation exactly
              // https://github.com/JannisX11/hytale-blockbench-plugin/blob/main/src/blockymodel.ts

              const angle = layout.angle || 0;

              // Get face dimensions (raw pixel size, not stretched)
              // left/right use depth for width, top/bottom use depth for height
              let uv_size = [0, 0];
              if (faceName === 'left' || faceName === 'right') {
                uv_size = [pixelD, pixelH];
              } else if (faceName === 'top' || faceName === 'bottom') {
                uv_size = [pixelW, pixelD];
              } else { // front, back
                uv_size = [pixelW, pixelH];
              }

              // Mirror multipliers: true = -1, false = 1
              let uv_mirror = [
                layout.mirror?.x ? -1 : 1,
                layout.mirror?.y ? -1 : 1
              ];

              const uv_offset = [layout.offset.x, layout.offset.y];

              // Calculate UV result [u1, v1, u2, v2] based on rotation
              // This matches Blockbench plugin's parse() function
              let result;
              switch (angle) {
                case 90: {
                  // Swap size and mirror indices, flip mirror[0]
                  [uv_size[0], uv_size[1]] = [uv_size[1], uv_size[0]];
                  [uv_mirror[0], uv_mirror[1]] = [uv_mirror[1], uv_mirror[0]];
                  uv_mirror[0] *= -1;
                  result = [
                    uv_offset[0],
                    uv_offset[1] + uv_size[1] * uv_mirror[1],
                    uv_offset[0] + uv_size[0] * uv_mirror[0],
                    uv_offset[1]
                  ];
                  break;
                }
                case 180: {
                  uv_mirror[0] *= -1;
                  uv_mirror[1] *= -1;
                  result = [
                    uv_offset[0] + uv_size[0] * uv_mirror[0],
                    uv_offset[1] + uv_size[1] * uv_mirror[1],
                    uv_offset[0],
                    uv_offset[1]
                  ];
                  break;
                }
                case 270: {
                  [uv_size[0], uv_size[1]] = [uv_size[1], uv_size[0]];
                  [uv_mirror[0], uv_mirror[1]] = [uv_mirror[1], uv_mirror[0]];
                  uv_mirror[1] *= -1;
                  result = [
                    uv_offset[0] + uv_size[0] * uv_mirror[0],
                    uv_offset[1],
                    uv_offset[0],
                    uv_offset[1] + uv_size[1] * uv_mirror[1]
                  ];
                  break;
                }
                default: { // 0
                  result = [
                    uv_offset[0],
                    uv_offset[1],
                    uv_offset[0] + uv_size[0] * uv_mirror[0],
                    uv_offset[1] + uv_size[1] * uv_mirror[1]
                  ];
                  break;
                }
              }

              // Convert pixel coords to normalized UV (0-1)
              // Blockbench/Hytale uses Y=0 at top, OpenGL uses Y=0 at bottom
              const u1 = result[0] / texW;
              const v1 = 1.0 - result[1] / texH;
              const u2 = result[2] / texW;
              const v2 = 1.0 - result[3] / texH;

              // Three.js BoxGeometry vertex order per face: TL, TR, BL, BR
              // with default UVs [0,1], [1,1], [0,0], [1,0]
              // Blockbench result is [u1,v1,u2,v2] = [left,top,right,bottom] in image coords
              const baseIdx = faceIdx * 4 * 2;
              uvArray[baseIdx + 0] = u1; uvArray[baseIdx + 1] = v1;  // TL
              uvArray[baseIdx + 2] = u2; uvArray[baseIdx + 3] = v1;  // TR
              uvArray[baseIdx + 4] = u1; uvArray[baseIdx + 5] = v2;  // BL
              uvArray[baseIdx + 6] = u2; uvArray[baseIdx + 7] = v2;  // BR
            }
          }
          uvAttr.needsUpdate = true;
        }
      }

      const needsDoubleSide = flipX || flipY || flipZ;

      let material;
      if (texture) {
        // For body parts, don't use alphaTest - the neck texture region has sparse data
        // but should still render as solid skin-colored mesh
        const isBodyPart = ['Neck', 'Head', 'Chest', 'Belly', 'Pelvis'].includes(nodeName) ||
                           nodeName.includes('Arm') || nodeName.includes('Leg') ||
                           nodeName.includes('Hand') || nodeName.includes('Foot') ||
                           nodeName.includes('Thigh') || nodeName.includes('Calf');
        material = new THREE.MeshLambertMaterial({
          map: texture,
          wireframe: wireframeMode,
          alphaTest: isBodyPart ? 0 : 0.1,
          transparent: !isBodyPart,
          side: needsDoubleSide ? THREE.DoubleSide : THREE.FrontSide,
          depthWrite: true,
          polygonOffset: usePolygonOffset,
          polygonOffsetFactor: usePolygonOffset ? 1 : 0,
          polygonOffsetUnits: usePolygonOffset ? 1 : 0
        });
      } else {
        material = new THREE.MeshLambertMaterial({
          color: color,
          wireframe: wireframeMode,
          side: needsDoubleSide ? THREE.DoubleSide : THREE.FrontSide,
          polygonOffset: usePolygonOffset,
          polygonOffsetFactor: usePolygonOffset ? 1 : 0,
          polygonOffsetUnits: usePolygonOffset ? 1 : 0
        });
      }

      const mesh = new THREE.Mesh(geometry, material);

      // Apply flipping for negative stretch values
      if (flipX) mesh.scale.x = -1;
      if (flipY) mesh.scale.y = -1;
      if (flipZ) mesh.scale.z = -1;

      if (nodeName === 'Neck') {
        console.log('[DEBUG] Neck mesh created successfully');
      }

      return mesh;
    }

    // Simple working quad mesh - use PlaneGeometry like before
    // renderOrder parameter helps with transparent quad layering
    function createQuadMesh(shape, color, nodeName, texture = null, renderOrder = 0) {
      const settings = shape.settings;
      if (!settings || !settings.size) return null;

      const stretch = shape.stretch || { x: 1, y: 1, z: 1 };
      const sx = Math.abs(stretch.x || 1);
      const sy = Math.abs(stretch.y || 1);
      const sz = Math.abs(stretch.z || 1);

      const flipX = (stretch.x || 1) < 0;
      const flipY = (stretch.y || 1) < 0;

      const normal = settings.normal || '+Z';
      const pixelW = settings.size.x;
      const pixelH = settings.size.y;

      // Size in world units
      let width, height;
      if (normal === '+Z' || normal === '-Z') {
        width = pixelW * sx * SCALE;
        height = pixelH * sy * SCALE;
      } else if (normal === '+X' || normal === '-X') {
        width = pixelW * sz * SCALE;
        height = pixelH * sy * SCALE;
      } else { // +Y, -Y
        width = pixelW * sx * SCALE;
        height = pixelH * sz * SCALE;
      }

      const geometry = new THREE.PlaneGeometry(width, height);

      // Apply rotation based on normal direction
      if (normal === '-Z') {
        geometry.rotateY(Math.PI);
      } else if (normal === '+X') {
        geometry.rotateY(Math.PI / 2);
      } else if (normal === '-X') {
        geometry.rotateY(-Math.PI / 2);
      } else if (normal === '+Y') {
        geometry.rotateX(-Math.PI / 2);
      } else if (normal === '-Y') {
        geometry.rotateX(Math.PI / 2);
      }

      // Apply UV mapping if texture and textureLayout exist
      // Match Hytale's SetupQuadUV exactly (ModelRenderer.cs lines 352-386)
      const hasTextureLayout = texture && shape.textureLayout && shape.textureLayout.front;
      if (hasTextureLayout) {
        const texW = texture.image?.width || texture.userData?.width;
        const texH = texture.image?.height || texture.userData?.height;

        if (texW && texH) {
          const layout = shape.textureLayout.front;
          if (layout && layout.offset) {
            const angle = layout.angle || 0;
            const mirrorX = layout.mirror?.x || false;
            const mirrorY = layout.mirror?.y || false;

            // Simple UV calculation: offset is top-left corner in image coords (Y down)
            // Convert to OpenGL coords where V=0 is bottom, V=1 is top
            const x = layout.offset.x;
            const x2 = layout.offset.x + (mirrorX ? -1 : 1) * pixelW;
            // In image coords: offset.y is from top, offset.y + height is bottom
            // In OpenGL: top of region = 1 - offset.y/texH, bottom = 1 - (offset.y + height)/texH
            const vTop = 1.0 - layout.offset.y / texH;
            const vBottom = 1.0 - (layout.offset.y + (mirrorY ? -1 : 1) * pixelH) / texH;

            // UV corners: TL, TR, BL, BR (in screen space, matching PlaneGeometry vertex order)
            let uvs = [
              [x / texW, vTop],           // TL: left edge, top edge
              [x2 / texW, vTop],          // TR: right edge, top edge
              [x / texW, vBottom],        // BL: left edge, bottom edge
              [x2 / texW, vBottom]        // BR: right edge, bottom edge
            ];

            // Apply rotation if needed
            if (angle !== 0) {
              const cx = (x + x2) / 2 / texW;  // center U
              const cy = (vTop + vBottom) / 2;  // center V
              const rad = -angle * Math.PI / 180;  // negative because we rotate UVs opposite to visual rotation
              const cos = Math.cos(rad);
              const sin = Math.sin(rad);
              uvs = uvs.map(function(uv) {
                const du = uv[0] - cx;
                const dv = uv[1] - cy;
                return [cx + du * cos - dv * sin, cy + du * sin + dv * cos];
              });
            }

            // PlaneGeometry vertices: TopLeft(0), TopRight(1), BottomLeft(2), BottomRight(3)
            // Map Hytale order [TR, TL, BL, BR] to PlaneGeometry order [TL, TR, BL, BR]
            // PlaneGeometry vertex order: TL(0), TR(1), BL(2), BR(3)
            // Our uvs array is already in this order: [TL, TR, BL, BR]
            const newUVs = new Float32Array([
              uvs[0][0], uvs[0][1],  // vertex 0: TL
              uvs[1][0], uvs[1][1],  // vertex 1: TR
              uvs[2][0], uvs[2][1],  // vertex 2: BL
              uvs[3][0], uvs[3][1]   // vertex 3: BR
            ]);
            geometry.setAttribute('uv', new THREE.BufferAttribute(newUVs, 2));

          }
        }
      }

      let material;
      if (texture) {
        material = new THREE.MeshLambertMaterial({
          map: texture,
          wireframe: wireframeMode,
          alphaTest: 0.5,
          transparent: false,
          side: THREE.DoubleSide,
          depthWrite: true,
          depthTest: true
        });
      } else {
        material = new THREE.MeshLambertMaterial({
          color: color,
          wireframe: wireframeMode,
          side: THREE.DoubleSide
        });
      }

      const mesh = new THREE.Mesh(geometry, material);

      // Set render order for proper layering
      if (renderOrder !== 0) {
        mesh.renderOrder = renderOrder;
      }

      // Apply flipping for negative stretch
      if (flipX) mesh.scale.x = -1;
      if (flipY) mesh.scale.y = -1;

      return mesh;
    }

    // Official skin tone data from GradientSets.json
    const SKIN_TONES = {
      // Human/realistic skin tones (01-18, 27, 48, 52)
      '01': { color: 0xf4c39a, texture: 'TintGradients/Skin_Tones/01.png' }, // Light peach
      '02': { color: 0xf5c490, texture: 'TintGradients/Skin_Tones/02.png' }, // Warm peach
      '03': { color: 0xe0ae72, texture: 'TintGradients/Skin_Tones/03.png' }, // Light tan
      '04': { color: 0xba7f5b, texture: 'TintGradients/Skin_Tones/04.png' }, // Medium tan
      '05': { color: 0x945d44, texture: 'TintGradients/Skin_Tones/05.png' }, // Brown
      '06': { color: 0x6f3b2c, texture: 'TintGradients/Skin_Tones/06.png' }, // Dark brown
      '07': { color: 0x4f2a24, texture: 'TintGradients/Skin_Tones/07.png' }, // Very dark brown
      '08': { color: 0xdcc7a8, texture: 'TintGradients/Skin_Tones/08.png' }, // Pale olive
      '09': { color: 0xf5bc83, texture: 'TintGradients/Skin_Tones/09.png' }, // Golden
      '10': { color: 0xd98c5b, texture: 'TintGradients/Skin_Tones/10.png' }, // Warm tan
      '11': { color: 0xab7a4c, texture: 'TintGradients/Skin_Tones/11.png' }, // Caramel
      '12': { color: 0x7d432b, texture: 'TintGradients/Skin_Tones/12.png' }, // Chestnut
      '13': { color: 0x513425, texture: 'TintGradients/Skin_Tones/13.png' }, // Dark chestnut
      '14': { color: 0x31221f, texture: 'TintGradients/Skin_Tones/14.png' }, // Near black
      '15': { color: 0xd5a082, texture: 'TintGradients/Skin_Tones/15.png' }, // Rose beige
      '16': { color: 0x63492f, texture: 'TintGradients/Skin_Tones/16.png' }, // Olive brown
      '17': { color: 0x5e3a2f, texture: 'TintGradients/Skin_Tones/17.png' }, // Warm brown
      '18': { color: 0x4d272b, texture: 'TintGradients/Skin_Tones/18.png' }, // Dark reddish
      '27': { color: 0x765e48, texture: 'TintGradients/Skin_Tones/27.png' }, // Taupe
      '48': { color: 0xdcc5b0, texture: 'TintGradients/Skin_Tones/48.png' }, // Light beige
      '52': { color: 0x131111, texture: 'TintGradients/Skin_Tones/52.png' }, // Black
      // Fantasy skin tones - Blue (19, 25, 32, 33, 42)
      '19': { color: 0x8aacfb, texture: 'TintGradients/Skin_Tones/19.png' }, // Light blue
      '25': { color: 0x4354e6, texture: 'TintGradients/Skin_Tones/25.png' }, // Bright blue
      '32': { color: 0x3276c3, texture: 'TintGradients/Skin_Tones/32.png' }, // Medium blue
      '33': { color: 0x092029, texture: 'TintGradients/Skin_Tones/33.png' }, // Dark blue/teal
      '42': { color: 0xa0dfff, texture: 'TintGradients/Skin_Tones/42.png' }, // Pale ice blue
      // Fantasy skin tones - Purple (20, 26, 46, 47, 49)
      '20': { color: 0xa78af1, texture: 'TintGradients/Skin_Tones/20.png' }, // Light purple
      '26': { color: 0x6c2abd, texture: 'TintGradients/Skin_Tones/26.png' }, // Deep purple
      '46': { color: 0xddbfe8, texture: 'TintGradients/Skin_Tones/46.png' }, // Lavender
      '47': { color: 0xf0b9f2, texture: 'TintGradients/Skin_Tones/47.png' }, // Light lavender
      '49': { color: 0xec6ff7, texture: 'TintGradients/Skin_Tones/49.png' }, // Bright pink/purple
      // Fantasy skin tones - Green (22, 30, 35, 45)
      '22': { color: 0x9bc55d, texture: 'TintGradients/Skin_Tones/22.png' }, // Light green
      '30': { color: 0x50843a, texture: 'TintGradients/Skin_Tones/30.png' }, // Dark green (orc)
      '35': { color: 0x5eae37, texture: 'TintGradients/Skin_Tones/35.png' }, // Bright green (goblin)
      '45': { color: 0xd5f0a0, texture: 'TintGradients/Skin_Tones/45.png' }, // Pale green
      // Fantasy skin tones - Red/Pink (21, 31, 36, 38, 41)
      '21': { color: 0xfc8572, texture: 'TintGradients/Skin_Tones/21.png' }, // Coral/salmon
      '31': { color: 0xb22a2a, texture: 'TintGradients/Skin_Tones/31.png' }, // Red (demon)
      '36': { color: 0xff72c2, texture: 'TintGradients/Skin_Tones/36.png' }, // Hot pink
      '38': { color: 0x6c3f40, texture: 'TintGradients/Skin_Tones/38.png' }, // Dark reddish brown
      '41': { color: 0xff95cd, texture: 'TintGradients/Skin_Tones/41.png' }, // Light pink
      // Fantasy skin tones - Other (28, 29, 37, 39, 50, 51)
      '28': { color: 0xf3f3f3, texture: 'TintGradients/Skin_Tones/28.png' }, // White/pale
      '29': { color: 0x998d71, texture: 'TintGradients/Skin_Tones/29.png' }, // Olive/stone
      '37': { color: 0xf4c944, texture: 'TintGradients/Skin_Tones/37.png' }, // Yellow/gold
      '39': { color: 0xff9c5b, texture: 'TintGradients/Skin_Tones/39.png' }, // Orange
      '50': { color: 0x2b2b2f, texture: 'TintGradients/Skin_Tones/50.png' }, // Dark grey
      '51': { color: 0xf06f47, texture: 'TintGradients/Skin_Tones/51.png' }, // Deep orange
    };

    // Friendly aliases for skin tones
    const SKIN_TONE_ALIASES = {
      // Human-readable names
      'LightPeach': '01', 'WarmPeach': '02', 'LightTan': '03', 'MediumTan': '04',
      'Brown': '05', 'DarkBrown': '06', 'VeryDarkBrown': '07', 'PaleOlive': '08',
      'Golden': '09', 'WarmTan': '10', 'Caramel': '11', 'Chestnut': '12',
      'DarkChestnut': '13', 'NearBlack': '14', 'RoseBeige': '15',
      // Legacy names for backwards compatibility
      'Warm1': '01', 'Warm2': '02', 'Warm3': '03', 'Warm4': '04', 'Warm5': '05',
      'Cool1': '06', 'Cool2': '07', 'Cool3': '08', 'Cool4': '09', 'Cool5': '10',
      'Neutral1': '11', 'Neutral2': '12', 'Neutral3': '13', 'Neutral4': '14', 'Neutral5': '15',
      // Fantasy race shortcuts
      'Orc': '30', 'Goblin': '35', 'LightOrc': '22', 'DarkOrc': '30',
      'IceElf': '42', 'DarkElf': '26', 'NightElf': '33', 'HighElf': '46',
      'Demon': '31', 'Tiefling': '21', 'FireDemon': '31',
      'Undead': '50', 'Zombie': '29', 'Ghost': '28', 'Vampire': '52',
      'Fairy': '47', 'Pixie': '49', 'Dryad': '45',
      'Dwarf': '04', 'Gnome': '39',
      // Color-based shortcuts
      'Green': '35', 'LightGreen': '22', 'DarkGreen': '30', 'PaleGreen': '45',
      'Blue': '32', 'LightBlue': '19', 'DarkBlue': '33', 'IceBlue': '42',
      'Purple': '26', 'LightPurple': '20', 'Lavender': '46',
      'Red': '31', 'Pink': '36', 'LightPink': '41',
      'White': '28', 'Grey': '50', 'Black': '52',
      'Yellow': '37', 'Gold': '37', 'Orange': '39',
    };

    function getSkinToneColor(tone) {
      // Check if it's a direct ID (01-52)
      if (SKIN_TONES[tone]) {
        return SKIN_TONES[tone].color;
      }
      // Check aliases
      const aliasId = SKIN_TONE_ALIASES[tone];
      if (aliasId && SKIN_TONES[aliasId]) {
        return SKIN_TONES[aliasId].color;
      }
      // Default to light peach
      return SKIN_TONES['01'].color;
    }

    function getSkinToneGradientPath(tone) {
      // Check if it's a direct ID (01-52)
      if (SKIN_TONES[tone]) {
        return SKIN_TONES[tone].texture;
      }
      // Check aliases
      const aliasId = SKIN_TONE_ALIASES[tone];
      if (aliasId && SKIN_TONES[aliasId]) {
        return SKIN_TONES[aliasId].texture;
      }
      // Default to light peach
      return SKIN_TONES['01'].texture;
    }

    function getPartColor(part) {
      if (!part) return null;
      if (part.baseColor) {
        const bc = Array.isArray(part.baseColor) ? part.baseColor[0] : part.baseColor;
        if (typeof bc === 'string' && bc.startsWith('#')) {
          return parseInt(bc.slice(1), 16);
        }
      }
      return null;
    }

    function getDefaultColor(type, skinColor) {
      const defaults = {
        'haircut': 0x4a3728, 'facialHair': 0x4a3728, 'eyebrows': 0x4a3728,
        'pants': 0x2c3e50, 'overpants': 0x34495e,
        'undertop': 0x5dade2, 'overtop': 0x2980b9,
        'shoes': 0x1a1a1a, 'gloves': 0x8b4513,
        'face': skinColor, 'mouth': 0xc0392b, 'ears': skinColor,
        'eyes': 0x3498db,
        'underwear': 0xecf0f1,
        'cape': 0x8e44ad,
        'headAccessory': 0xf1c40f, 'faceAccessory': 0xbdc3c7, 'earAccessory': 0xf1c40f
      };
      return defaults[type] || 0x888888;
    }

    function animate() {
      requestAnimationFrame(animate);

      // Update animation time
      const now = performance.now();
      const deltaTime = (now - lastFrameTime) / 1000; // seconds
      lastFrameTime = now;

      // Apply current animation
      if (animationEnabled && currentAnimation) {
        // Clamp delta time to prevent large jumps (e.g., when tab is backgrounded)
        const clampedDelta = Math.min(deltaTime, 0.1); // Max 100ms per frame
        animationTime += clampedDelta * FPS; // Convert to frames
        if (currentAnimation.holdLastKeyframe) {
          animationTime = Math.min(animationTime, currentAnimation.duration);
        }
        // applyAnimation handles looping internally with smooth interpolation
        applyAnimation(currentAnimation, animationTime);
      }

      if (autoRotate) character.rotation.y += 0.005;
      else if (rotationSpeed) character.rotation.y += rotationSpeed;
      renderer.render(scene, camera);
    }

    // Debug function - call from console: debugHierarchy()
    window.debugHierarchy = function() {
      console.log('=== CHARACTER HIERARCHY DEBUG ===');
      const bones = ['Origin', 'Pelvis', 'Belly', 'Chest', 'Head', 'L-Shoulder', 'R-Shoulder', 'L-Thigh', 'R-Thigh'];
      bones.forEach(name => {
        const obj = scene.getObjectByName(name);
        if (obj) {
          const worldPos = new THREE.Vector3();
          obj.getWorldPosition(worldPos);
          const localPos = obj.position;
          const parent = obj.parent ? obj.parent.name : 'none';
          console.log(name + ':');
          console.log('  local: (' + localPos.x.toFixed(3) + ', ' + localPos.y.toFixed(3) + ', ' + localPos.z.toFixed(3) + ')');
          console.log('  world: (' + worldPos.x.toFixed(3) + ', ' + worldPos.y.toFixed(3) + ', ' + worldPos.z.toFixed(3) + ')');
          console.log('  parent: ' + parent);
        } else {
          console.log(name + ': NOT FOUND');
        }
      });
      console.log('=== END DEBUG ===');
    };

    // Debug function - call from console: debugMeshes()
    window.debugMeshes = function() {
      console.log('=== MESH DEBUG ===');
      character.traverse(obj => {
        if (obj.isMesh) {
          const worldPos = new THREE.Vector3();
          obj.getWorldPosition(worldPos);
          const bbox = new THREE.Box3().setFromObject(obj);
          const size = new THREE.Vector3();
          bbox.getSize(size);
          console.log(obj.name || '(unnamed mesh)' + ':');
          console.log('  world pos: (' + worldPos.x.toFixed(3) + ', ' + worldPos.y.toFixed(3) + ', ' + worldPos.z.toFixed(3) + ')');
          console.log('  bbox size: (' + size.x.toFixed(3) + ', ' + size.y.toFixed(3) + ', ' + size.z.toFixed(3) + ')');
        }
      });
      console.log('=== END MESH DEBUG ===');
    };

    // Debug specific bone group (e.g., "Head") to check pivot vs mesh offset
    window.debugBoneGroup = function(boneName = 'Head') {
      console.log('=== DEBUG BONE GROUP: ' + boneName + ' ===');
      const boneGroup = scene.getObjectByName(boneName);
      if (!boneGroup) {
        console.log('Bone not found: ' + boneName);
        return;
      }

      const groupWorldPos = new THREE.Vector3();
      boneGroup.getWorldPosition(groupWorldPos);
      console.log('Group (pivot) world pos:', groupWorldPos.x.toFixed(3), groupWorldPos.y.toFixed(3), groupWorldPos.z.toFixed(3));
      console.log('Group local pos:', boneGroup.position.x.toFixed(3), boneGroup.position.y.toFixed(3), boneGroup.position.z.toFixed(3));

      boneGroup.children.forEach((child, idx) => {
        if (child.isMesh) {
          const meshWorldPos = new THREE.Vector3();
          child.getWorldPosition(meshWorldPos);
          const params = child.geometry.parameters;

          console.log('');
          console.log('Mesh ' + idx + ' (' + (child.parent?.name || 'unnamed') + '):');
          console.log('  Local Pos:', child.position.x.toFixed(3), child.position.y.toFixed(3), child.position.z.toFixed(3));
          console.log('  World Pos:', meshWorldPos.x.toFixed(3), meshWorldPos.y.toFixed(3), meshWorldPos.z.toFixed(3));
          console.log('  Geometry Size:', params?.width?.toFixed(3), params?.height?.toFixed(3), params?.depth?.toFixed(3));
          console.log('  Scale:', child.scale.x.toFixed(2), child.scale.y.toFixed(2), child.scale.z.toFixed(2));

          // Check offset from pivot
          const offsetFromPivot = new THREE.Vector3().subVectors(meshWorldPos, groupWorldPos);
          console.log('  Offset from pivot:', offsetFromPivot.x.toFixed(3), offsetFromPivot.y.toFixed(3), offsetFromPivot.z.toFixed(3));
        } else if (child.isGroup) {
          console.log('');
          console.log('Nested Group: ' + child.name);
        }
      });
      console.log('=== END BONE GROUP DEBUG ===');
    };

    // Debug arm chain specifically
    window.debugArms = function() {
      console.log('=== ARM CHAIN DEBUG ===');
      const armBones = ['L-Shoulder', 'L-Arm', 'L-Forearm', 'L-Hand', 'R-Shoulder', 'R-Arm', 'R-Forearm', 'R-Hand'];
      armBones.forEach(name => {
        const bone = scene.getObjectByName(name);
        if (bone) {
          const worldPos = new THREE.Vector3();
          bone.getWorldPosition(worldPos);
          const euler = new THREE.Euler().setFromQuaternion(bone.quaternion);
          console.log(name + ':');
          console.log('  local: (' + bone.position.x.toFixed(3) + ', ' + bone.position.y.toFixed(3) + ', ' + bone.position.z.toFixed(3) + ')');
          console.log('  world: (' + worldPos.x.toFixed(3) + ', ' + worldPos.y.toFixed(3) + ', ' + worldPos.z.toFixed(3) + ')');
          console.log('  rot(deg): (' + (euler.x * 180/Math.PI).toFixed(1) + ', ' + (euler.y * 180/Math.PI).toFixed(1) + ', ' + (euler.z * 180/Math.PI).toFixed(1) + ')');
          console.log('  parent: ' + (bone.parent?.name || 'none'));
        }
      });
      console.log('=== END ARM DEBUG ===');
    };

    // Debug all cosmetic pieces (find by _cosmetic suffix)
    window.debugCosmetics = function() {
      console.log('=== COSMETIC DEBUG ===');
      character.traverse((obj) => {
        if (obj.name && obj.name.endsWith('_cosmetic')) {
          const worldPos = new THREE.Vector3();
          obj.getWorldPosition(worldPos);
          const euler = new THREE.Euler().setFromQuaternion(obj.quaternion);
          console.log(obj.name + ':');
          console.log('  local pos: (' + obj.position.x.toFixed(3) + ', ' + obj.position.y.toFixed(3) + ', ' + obj.position.z.toFixed(3) + ')');
          console.log('  world pos: (' + worldPos.x.toFixed(3) + ', ' + worldPos.y.toFixed(3) + ', ' + worldPos.z.toFixed(3) + ')');
          console.log('  rotation (deg): (' + (euler.x * 180/Math.PI).toFixed(1) + ', ' + (euler.y * 180/Math.PI).toFixed(1) + ', ' + (euler.z * 180/Math.PI).toFixed(1) + ')');
          console.log('  parent: ' + (obj.parent?.name || 'none'));
          // Show meshes in this group
          obj.children.forEach((child, i) => {
            if (child.isMesh) {
              const meshWorld = new THREE.Vector3();
              child.getWorldPosition(meshWorld);
              console.log('  mesh[' + i + '] local: (' + child.position.x.toFixed(3) + ', ' + child.position.y.toFixed(3) + ', ' + child.position.z.toFixed(3) + ')');
              console.log('  mesh[' + i + '] world: (' + meshWorld.x.toFixed(3) + ', ' + meshWorld.y.toFixed(3) + ', ' + meshWorld.z.toFixed(3) + ')');
            }
          });
        }
      });
      console.log('=== END COSMETIC DEBUG ===');
    };

    init();
  </script>
</body>
</html>`;
}

// Start server
console.log('=== Hytale Auth Server ===');
console.log(`Domain: ${DOMAIN}`);
console.log(`Data directory: ${DATA_DIR}`);
console.log(`Assets path: ${ASSETS_PATH}`);

// Pre-load cosmetics on startup
if (fs.existsSync(ASSETS_PATH)) {
  console.log('Assets.zip found, loading cosmetics...');
  loadCosmeticsFromAssets();
} else {
  console.log('Assets.zip not found, using fallback cosmetics');
}

// Initialize Redis and start server
async function startServer() {
  // Connect to Redis
  await initializeRedis();

  const server = http.createServer(handleRequest);
  server.listen(PORT, '0.0.0.0', () => {
    const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Main';
    console.log(`[${workerId}] Server running on port ${PORT}`);
    console.log(`[${workerId}] Redis: ${redisConnected ? 'connected' : 'NOT CONNECTED'}`);
    // Only show endpoints once (first worker or single process)
    if (!cluster.isWorker || cluster.worker.id === 1) {
      console.log(`Endpoints:`);
      console.log(`  - sessions.${DOMAIN}`);
      console.log(`  - account-data.${DOMAIN}`);
      console.log(`  - telemetry.${DOMAIN}`);
      console.log(`  - Avatar viewer: /avatar/{uuid}`);
      console.log(`  - Avatar customizer: /customizer/{uuid}`);
      console.log(`  - Cosmetics list: /cosmetics/list`);
      console.log(`  - Asset extraction: /asset/{path}`);
      console.log(`  - Admin dashboard: /admin`);
      console.log(`  - Admin API: /admin/sessions, /admin/stats`);
    }
  });
}

// Cluster mode: primary spawns workers, workers handle requests
if (cluster.isPrimary && NUM_WORKERS > 1) {
  console.log(`Primary ${process.pid} starting ${NUM_WORKERS} workers...`);

  for (let i = 0; i < NUM_WORKERS; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died (${signal || code}). Restarting...`);
    cluster.fork();
  });

  cluster.on('online', (worker) => {
    console.log(`Worker ${worker.process.pid} is online`);
  });
} else {
  // Worker process or single-process mode
  startServer().catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}
