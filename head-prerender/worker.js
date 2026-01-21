const puppeteer = require('puppeteer');
const Redis = require('ioredis');
const fs = require('fs');
const path = require('path');

// Configuration
const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || 'http://hytale-auth:3000';
const REDIS_URL = process.env.REDIS_URL || 'redis://kvrocks:6666';
const HEAD_CACHE_DIR = process.env.HEAD_CACHE_DIR || '/app/data/head-cache';
const BG_COLOR = process.env.BG_COLOR || 'black';
const RENDER_TIMEOUT = parseInt(process.env.RENDER_TIMEOUT) || 10000;
const BATCH_SIZE = parseInt(process.env.BATCH_SIZE) || 5;
const LOOP_INTERVAL = parseInt(process.env.LOOP_INTERVAL) || 60000; // 1 minute between loops
const HEAD_CACHE_TTL = 3600000; // 1 hour (same as auth server)

// Redis key prefixes (same as auth server)
const REDIS_KEYS = {
  SERVER_PLAYERS: 'server:',
};

// Redis client
const redis = new Redis(REDIS_URL, {
  retryDelayOnFailover: 100,
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});

let redisConnected = false;

redis.on('connect', () => {
  console.log('Connected to Redis');
  redisConnected = true;
});

redis.on('error', (err) => {
  console.error('Redis error:', err.message);
  redisConnected = false;
});

// Ensure cache directory exists
function ensureCacheDir() {
  if (!fs.existsSync(HEAD_CACHE_DIR)) {
    fs.mkdirSync(HEAD_CACHE_DIR, { recursive: true });
    console.log(`Created cache directory: ${HEAD_CACHE_DIR}`);
  }
}

// Check if head is already cached and not expired
function isCached(uuid) {
  const cacheKey = `${uuid}_${BG_COLOR}`;
  const filePath = path.join(HEAD_CACHE_DIR, `${cacheKey}.png`);

  if (!fs.existsSync(filePath)) return false;

  const stats = fs.statSync(filePath);
  const age = Date.now() - stats.mtimeMs;

  if (age > HEAD_CACHE_TTL) {
    // Expired, delete it
    fs.unlinkSync(filePath);
    return false;
  }

  return true;
}

// Get all active player UUIDs from Redis
async function getActivePlayerUuids() {
  if (!redisConnected) return [];

  try {
    const serverKeys = [];
    let cursor = '0';
    do {
      const [newCursor, keys] = await redis.scan(cursor, 'MATCH', `${REDIS_KEYS.SERVER_PLAYERS}*`, 'COUNT', 500);
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
    console.error('Error getting player UUIDs:', e.message);
    return [];
  }
}

// Get UUIDs that need rendering
async function getUncachedUuids() {
  const allUuids = await getActivePlayerUuids();
  return allUuids.filter(uuid => !isCached(uuid));
}

// Render a single head using Puppeteer
async function renderHead(browser, uuid) {
  const page = await browser.newPage();

  try {
    // Set viewport
    await page.setViewport({ width: 256, height: 256 });

    // Navigate to head embed page
    const url = `${AUTH_SERVER_URL}/avatar/${uuid}/head?bg=${BG_COLOR}`;
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: RENDER_TIMEOUT });

    // Wait for canvas to appear (Three.js creates it)
    await page.waitForSelector('canvas', { timeout: RENDER_TIMEOUT });

    // Wait for the avatar to load and render
    // The page calls viewer.loadAvatar() which fetches model data
    // Give time for: Three.js init + model fetch + render + POST cache
    await new Promise(r => setTimeout(r, 5000));

    // Check if the server already has the cached image now
    // (the embed page POSTs the rendered image back)
    if (isCached(uuid)) {
      console.log(`  [OK] ${uuid}`);
      return true;
    }

    // Wait a bit more and check again
    await new Promise(r => setTimeout(r, 2000));
    if (isCached(uuid)) {
      console.log(`  [OK] ${uuid}`);
      return true;
    }

    // Not cached - user data might not exist, skip
    console.log(`  [SKIP] ${uuid} - no cache created`);
    return false;
  } catch (e) {
    // Silently skip failures (user data not found, etc)
    console.log(`  [SKIP] ${uuid}`);
    return false;
  } finally {
    await page.close();
  }
}

// Process a batch of UUIDs
async function processBatch(browser, uuids) {
  const results = { success: 0, failed: 0 };

  for (const uuid of uuids) {
    const success = await renderHead(browser, uuid);
    if (success) results.success++;
    else results.failed++;
  }

  return results;
}

// Main worker loop
async function runWorker() {
  console.log('=== Head Pre-render Worker ===');
  console.log(`Auth server: ${AUTH_SERVER_URL}`);
  console.log(`Redis: ${REDIS_URL}`);
  console.log(`Cache dir: ${HEAD_CACHE_DIR}`);
  console.log(`Background: ${BG_COLOR}`);
  console.log(`Batch size: ${BATCH_SIZE}`);
  console.log(`Loop interval: ${LOOP_INTERVAL}ms`);
  console.log('');

  ensureCacheDir();

  // Connect to Redis
  await redis.connect();

  // Launch browser with WebGL support
  console.log('Launching browser...');
  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-web-security',
      '--allow-file-access-from-files'
    ]
  });
  console.log('Browser ready');

  // Main loop
  while (true) {
    try {
      const uncached = await getUncachedUuids();

      if (uncached.length === 0) {
        console.log(`[${new Date().toISOString()}] All heads cached, sleeping...`);
      } else {
        console.log(`[${new Date().toISOString()}] Found ${uncached.length} uncached heads`);

        // Process in batches
        for (let i = 0; i < uncached.length; i += BATCH_SIZE) {
          const batch = uncached.slice(i, i + BATCH_SIZE);
          console.log(`Processing batch ${Math.floor(i / BATCH_SIZE) + 1}/${Math.ceil(uncached.length / BATCH_SIZE)} (${batch.length} heads)`);

          const results = await processBatch(browser, batch);
          console.log(`  Batch complete: ${results.success} success, ${results.failed} failed`);

          // Small delay between batches
          await new Promise(r => setTimeout(r, 1000));
        }
      }
    } catch (e) {
      console.error('Worker error:', e.message);
    }

    // Wait before next iteration
    await new Promise(r => setTimeout(r, LOOP_INTERVAL));
  }
}

// Handle shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down...');
  await redis.quit();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('Shutting down...');
  await redis.quit();
  process.exit(0);
});

// Start worker
runWorker().catch(err => {
  console.error('Worker failed:', err);
  process.exit(1);
});
