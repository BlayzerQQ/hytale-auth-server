FROM node:20-alpine

WORKDIR /app

# Install unzip for Assets.zip extraction
RUN apk add --no-cache unzip

# Create directories
RUN mkdir -p /app/data /app/assets

COPY server.js ./

EXPOSE 3000

CMD ["node", "server.js"]
