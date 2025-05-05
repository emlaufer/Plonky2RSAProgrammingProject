FROM node:23.11 AS build

# Set working directory
WORKDIR /app

# Install root dependencies
COPY package*.json ./
RUN npm install

# TODO: move this to github
# Install wasm plonky2 verifier
COPY ../plonky2-wasm-verify/pkg ./plonky2-wasm-verify/pkg

# Build server
COPY server ./server
RUN npm run build

# Build client
COPY client ./client
RUN npm install --prefix client && npm run build --prefix client

# Production image
FROM node:23.11-alpine
WORKDIR /app

# Install MongoDB client tools
RUN apk add --no-cache mongodb-tools

COPY --from=build /app/server/dist ./dist
COPY --from=build /app/client/dist ./client/dist
COPY package*.json ./
RUN npm install --only=production

ENV NODE_ENV=production
ENV PORT=5000
# Default MongoDB connection string - override this in production
EXPOSE 5000

CMD ["node", "dist/server.js"]
