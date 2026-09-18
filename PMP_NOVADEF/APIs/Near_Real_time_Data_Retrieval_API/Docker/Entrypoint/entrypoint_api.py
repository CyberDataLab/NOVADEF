#!/usr/bin/env python3
"""
Entrypoint for FastAPI WebSocket server.
Waits for Redis before starting the API.
"""

import os
import sys
import time
import socket
import subprocess


def check_redis_connection(host: str, port: int, max_attempts: int = 30) -> bool:
    """
    Check if Redis is available by attempting to connect.
    
    Args:
        host: Redis hostname
        port: Redis port
        max_attempts: Maximum connection attempts
    
    Returns:
        True if Redis is reachable, False otherwise
    """
    print(f"⏳ Waiting for Redis at {host}:{port}...")
    
    for attempt in range(1, max_attempts + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                print(f"✅ Redis is ready!")
                return True
            
        except socket.gaierror:
            print(f"   Attempt {attempt}/{max_attempts} - DNS resolution failed for {host}")
        except Exception as e:
            print(f"   Attempt {attempt}/{max_attempts} - Connection error: {e}")
        
        print(f"   Attempt {attempt}/{max_attempts} - Redis not ready yet...")
        time.sleep(2)
    
    print(f"❌ Redis failed to become ready after {max_attempts} attempts")
    return False


def main():
    """
    Main entrypoint logic: wait for Redis and start API server.
    """
    print("🚀 NRTDR API Entrypoint")
    print("=" * 50)
    
    # Get configuration from environment (all required)
    redis_host = os.getenv("REDIS_HOST")
    redis_port = int(os.getenv("REDIS_PORT"))
    api_host = os.getenv("NRTDR_API_HOST")
    api_port = int(os.getenv("NRTDR_API_PORT", "8001"))
    
    # Wait for Redis
    if not check_redis_connection(redis_host, redis_port):
        print("❌ Redis is not available, cannot start API")
        sys.exit(1)
    
    print()
    print("✅ Redis ready, starting API server...")
    print("Configuration:")
    print(f"  Redis Host: {redis_host}:{redis_port}")
    print(f"  API Host: {api_host}")
    print(f"  API Port: {api_port}")
    print(f"  WS default last_n: {os.getenv('NRTDR_WS_DEFAULT_LAST_N')}")
    print(f"  WS max last_n: {os.getenv('NRTDR_WS_MAX_LAST_N')}")
    print(f"  Active window: {os.getenv('NRTDR_ACTIVE_WINDOW_SECONDS')}s")
    print()
    
    # Execute Uvicorn
    try:
        subprocess.run(
            [
                "uvicorn",
                "api_server:app",
                "--host", api_host,
                "--port", str(api_port),
                "--log-level", "info",
                "--access-log"
            ],
            check=True,
            cwd="/home/nrtdr_api"
        )
    except subprocess.CalledProcessError as e:
        print(f"❌ API server exited with error code {e.returncode}")
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        print("\n🛑 API server interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
