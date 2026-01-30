const path = require('path');
const os = require('os');

// Configuration via environment variables
const config = {
  // Server
  port: parseInt(process.env.PORT) || 3000,
  domain: process.env.DOMAIN || 'sanasol.ws',
  workers: parseInt(process.env.WORKERS) || Math.min(os.cpus().length, 4),

  // Paths
  dataDir: './data',
  assetsPath: './assets/Assets.zip',

  // Redis
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',

  // Admin
  adminPassword: process.env.ADMIN_PASSWORD || 'changeme',
  adminTokenTtl: 86400, // 24 hours in seconds

  // Session
  sessionTtl: 36000, // 10 hours in seconds

  // JWT
  keyId: '2025-10-01-sanasol',

  // Cache
  headCacheTtl: 3600000, // 1 hour in milliseconds

  // DLE Database
  dleDb: {
    host: process.env.DLE_DB_HOST || 'localhost',
    port: parseInt(process.env.DLE_DB_PORT) || 3306,
    user: process.env.DLE_DB_USER || 'dle_user',
    password: process.env.DLE_DB_PASSWORD || 'dle_password',
    database: process.env.DLE_DB_NAME || 'dle_database'
  },

  // DLE Auth settings
  maxFailedAttempts: parseInt(process.env.MAX_FAILED_ATTEMPTS) || 5,
  lockTimeMinutes: parseInt(process.env.LOCK_TIME_MINUTES) || 5,
  minUsernameLength: parseInt(process.env.MIN_USERNAME_LENGTH) || 3,

  // Redis key prefixes
  redisKeys: {
    SESSION: 'session:',
    AUTH_GRANT: 'authgrant:',
    USER: 'user:',
    SERVER_PLAYERS: 'server:',
    PLAYER_SERVER: 'player:',
    USERNAME: 'username:',
    SERVER_NAME: 'servername:',
    ADMIN_TOKEN: 'admintoken:',
    DLE_USER: 'dle_user:', // Кэш пользователей DLE
    FAILED_LOGIN: 'failed_login:', // Неудачные попытки
  },
};

// Derived paths
config.keyFile = path.join(config.dataDir, 'jwt_keys.json');
config.headCacheDir = path.join(config.dataDir, 'head-cache');
config.downloadsDir = process.env.DOWNLOADS_DIR || path.join(config.dataDir, 'downloads');

module.exports = config;
