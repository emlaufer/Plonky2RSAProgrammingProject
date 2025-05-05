# Message Board App

A simple full-stack message board for students, built with React, Node.js, Express, and MongoDB. Fully typed with TypeScript, Dockerized for deployment, and ready for development with ESLint, Prettier, and tests.

## Features

- Post and view messages
- Express/MongoDB backend with Mongoose
- React frontend using TypeScript
- Docker support
- ESLint + Prettier configured
- Jest + React Testing Library for frontend tests

## Prerequisites

- [Node.js](https://nodejs.org/) (v14 or higher)
- [MongoDB](https://www.mongodb.com/) (v4.4 or higher)
- [Docker](https://www.docker.com/) (optional for containerized deployment)

## Getting Started

### 1. Set up Node.js

If you don't have Node.js installed:

```bash
# For Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs

# For macOS (using Homebrew)
brew install node

# Verify installation
node --version
npm --version
```

### 2. Set up MongoDB

```bash
# For Ubuntu/Debian
sudo apt-get install gnupg
wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
sudo apt-get update
sudo apt-get install -y mongodb-org

# Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# For macOS (using Homebrew)
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb-community

# Verify installation
mongod --version
```

### 3. Clone the repository

```bash
git clone https://github.com/your-username/message-board-app.git
cd message-board-app
```

### 4. Install dependencies

```bash
# Install server dependencies
npm install

# Install client dependencies
cd client && npm install
cd ..
```

### 5. Set up environment

Create a `.env` file in the `server` folder:

```env
MONGO_URI=mongodb://localhost:27017/messageboard
PORT=5000
```

### 6. Run the development server

```bash
# Start both server and client concurrently
npm run dev

# Server will run on http://localhost:5000
# Client will run on http://localhost:3000
```

This will:

- Start the Express server with hot reloading using nodemon
- Start the React development server
- Watch for file changes in both client and server

### 7. Build the app

To compile the server TypeScript files:

```bash
npm run build
```

To build the React frontend:

```bash
cd client
npm run build
```

## Linting & Formatting

- Run ESLint:
  ```bash
  npm run lint
  ```
- Run Prettier:
  ```bash
  npm run format
  ```

## Testing

Frontend tests are set up using React Testing Library.

To run tests:

```bash
cd client
npm test
```

## Docker Deployment

### Development Environment with Docker Compose

For development with hot reloading and a complete environment including MongoDB:

```bash
# Start the development environment
docker-compose up

# Access the application:
# - Frontend: http://localhost:3000
# - Backend API: http://localhost:5000
# - MongoDB: mongodb://localhost:27017/myapp
```

The development setup includes:

- Hot reloading for both client and server code
- MongoDB database container
- Volume mounts for live code changes
- Proper container networking and dependencies

To stop the development environment:

```bash
docker-compose down

# To remove volumes (will delete database data)
docker-compose down -v
```

### Build and run Docker container locally

```bash
docker build -t message-board-app .
docker run -p 5000:5000 --env-file server/.env message-board-app
```

### With Docker Compose (optional)

Create a `docker-compose.yml`:

```yaml
version: '3.9'
services:
  app:
    build: .
    ports:
      - '5000:5000'
    env_file:
      - server/.env
```

Run:

```bash
docker-compose up
```
