#!/usr/bin/env python3
"""
Entrypoint for Kafka to Redis worker.
Waits for dependencies (Redis and Kafka) before starting the worker.
"""

import os
import sys
import time
import socket


def check_tcp_connection(host: str, port: int, service_name: str, max_attempts: int = 30) -> bool:
    """
    Check if a TCP service is available by attempting to connect.
    
    Args:
        host: Service hostname
        port: Service port
        service_name: Name for logging
        max_attempts: Maximum connection attempts
    
    Returns:
        True if service is reachable, False otherwise
    """
    print(f"⏳ Waiting for {service_name} at {host}:{port}...")
    
    for attempt in range(1, max_attempts + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                print(f"✅ {service_name} is ready!")
                return True
            
        except socket.gaierror:
            print(f"   Attempt {attempt}/{max_attempts} - DNS resolution failed for {host}")
        except Exception as e:
            print(f"   Attempt {attempt}/{max_attempts} - Connection error: {e}")
        
        print(f"   Attempt {attempt}/{max_attempts} - {service_name} not ready yet...")
        time.sleep(2)
    
    print(f"❌ {service_name} failed to become ready after {max_attempts} attempts")
    return False


def main():
    """
    Main entrypoint logic: wait for dependencies and start worker.
    """
    print("🚀 Redis Worker Entrypoint")
    print("=" * 50)
    
    # Get configuration from environment (all required)
    redis_host = os.getenv("REDIS_HOST")
    redis_port = int(os.getenv("REDIS_PORT"))
    kafka_bootstrap = os.getenv("KAFKA_BOOTSTRAP_DOCKER") or os.getenv("KAFKA_BOOTSTRAP")
    
    # Parse Kafka host and port
    try:
        kafka_host, kafka_port_str = kafka_bootstrap.split(":")
        kafka_port = int(kafka_port_str)
    except ValueError:
        print(f"❌ Invalid Kafka bootstrap format: {kafka_bootstrap}")
        print("   Expected format: host:port")
        sys.exit(1)
    
    # Wait for Redis
    if not check_tcp_connection(redis_host, redis_port, "Redis"):
        print("❌ Redis is not available, cannot start worker")
        sys.exit(1)
    
    # Wait for Kafka
    if not check_tcp_connection(kafka_host, kafka_port, "Kafka"):
        print("❌ Kafka is not available, cannot start worker")
        sys.exit(1)
    
    print()
    print("✅ All dependencies ready, starting worker...")
    print("Configuration:")
    print(f"  Kafka Bootstrap: {kafka_bootstrap}")
    print(f"  Redis Host: {redis_host}:{redis_port}")
    print(f"  Consumer Group: {os.getenv('KTRW_KAFKA_GROUP_ID')}")
    print()
    
    # Replace the entrypoint process with the worker so the container lifecycle
    # and health checks reflect the actual long-running process.
    os.execvp(
        "python3",
        ["python3", "-u", "/home/redis_worker/kafka_redis_worker.py"],
    )


if __name__ == "__main__":
    main()
