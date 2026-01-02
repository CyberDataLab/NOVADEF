import subprocess
import sys
from pathlib import Path

def remove_containers():
    """
    Stops and removes containers, networks, and volumes for the active profiles defined in the .env file.
    """
    launcher_dir = Path(__file__).parent.resolve()
    env_file = launcher_dir / ".env"
    compose_file = launcher_dir / "docker-compose.yml"

    if not env_file.exists():
        print(f"⚠️  .env file not found in: {launcher_dir}")
        print("   Cannot determine PFD variables or active profiles. Aborting safety.")
        sys.exit(1)

    print(f"🧹 Starting complete cleanup (Containers + Networks + Volumes)...")
    print(f"   (Using configuration from: {env_file})")

    cmd = [
        "docker", "compose",
        "-f", str(compose_file),
        "--env-file", str(env_file),
        "down",
        "--volumes",
        "--remove-orphans"
    ]

    try:
        subprocess.run(cmd, check=True)
        print("\n✅ Cleanup completed successfully.")
        
    except subprocess.CalledProcessError:
        print("\n❌ Error: Cleanup failed. Please check your docker permissions.")
        sys.exit(1)

if __name__ == "__main__":
    remove_containers()