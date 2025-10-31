#!/bin/bash
# start_fresh.sh — elimina el volumen de Neo4j y levanta todo limpio

set -e  # salir en error
echo "🧹 Removing old Neo4j volume (if exists)..."
docker compose down --volumes --remove-orphans 2>/dev/null || true
docker volume rm $(docker volume ls -q | grep neo4j_data) 2>/dev/null || true

echo "🚀 Starting fresh environment..."
docker compose up -d
