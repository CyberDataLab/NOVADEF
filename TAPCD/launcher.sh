#!/bin/bash
# start_fresh.sh — elimina el volumen de Neo4j y levanta todo limpio

echo "🧹 Removing old Neo4j volume (if exists)..."
docker compose down --volumes --remove-orphans 2>/dev/null || true
NEO4J_VOLS=$(docker volume ls -q 2>/dev/null | grep neo4j_data || true)
[ -n "$NEO4J_VOLS" ] && docker volume rm $NEO4J_VOLS 2>/dev/null || true

echo "🚀 Starting fresh environment..."
docker compose up -d
