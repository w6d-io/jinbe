#!/bin/bash
# Quick Start Script for Kuma API
# This script sets up and runs the Kuma API in development mode

set -e  # Exit on error

echo "🚀 Kuma API - Quick Start"
echo "=========================="
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version must be 18 or higher. Current: $(node -v)"
    exit 1
fi

echo "✅ Node.js $(node -v) detected"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "📝 Creating .env file from .env.example..."
    cp .env.example .env
    echo "⚠️  IMPORTANT: Edit .env and set your configuration values!"
    echo "   Required: DATABASE_URL, JWT_SECRET, ENCRYPTION_KEY, COOKIE_SECRET"
    echo ""
    read -p "Press Enter after editing .env, or Ctrl+C to exit..."
fi

# Install dependencies
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    echo "✅ Dependencies installed"
    echo ""
else
    echo "✅ Dependencies already installed"
    echo ""
fi

# Generate Prisma Client
echo "🔧 Generating Prisma Client..."
npm run prisma:generate
echo "✅ Prisma Client generated"
echo ""

# Build TypeScript (optional for dev mode)
echo "🏗️  Building TypeScript..."
npm run build
if [ $? -eq 0 ]; then
    echo "✅ Build successful"
else
    echo "⚠️  Build had errors, but dev mode should still work"
fi
echo ""

# Start development server
echo "🎉 Starting development server..."
echo ""
echo "   Server will run at: http://localhost:3000"
echo "   API documentation: http://localhost:3000/docs"
echo "   Health check: http://localhost:3000/health"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

npm run dev
