# Use Google Chrome image with proper WebGL support
FROM ghcr.io/puppeteer/puppeteer:latest

USER root

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy worker script
COPY worker.js ./

# Run as root to avoid permission issues with shared volume
CMD ["node", "worker.js"]
