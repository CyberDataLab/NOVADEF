from pathlib import Path
import platform
import subprocess
import sys

def get_device_id():
    Dir_file = Path(__file__).resolve().parent
    system_name = platform.system().lower()
    if system_name == "windows":
        mid_path = Dir_file / "mid_windows" / "mid.exe"
        mid_binary = str(mid_path)
    else:
        mid_path = Dir_file / "mid_linux_macos" / "mid"
        mid_binary = str(mid_path)

    try:
        output = subprocess.check_output([mid_binary], stderr=subprocess.STDOUT)
        device_id = output.decode("utf-8").strip()
        return device_id
    except OSError as e:
        if e.errno == 8: # Exec format error (wrong architecture/OS)
            import hashlib
            import socket
            import uuid
            # Fallback for Mac M1/M2 or other architectures
            fallback_id = hashlib.sha256(f"{socket.gethostname()}-{uuid.getnode()}".encode()).hexdigest()
            return fallback_id
        else:
            raise e
    except FileNotFoundError:
        print(f"Binary not found '{mid_binary}'.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(
            f"Permission denied executing '{mid_binary}'. "
            f"The file likely lost its executable bit during copy/clone/unzip — "
            f"run: chmod +x '{mid_binary}'",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error while executing '{mid_binary}': {e.output.decode('utf-8')}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    device_id = get_device_id()
    print(f"{device_id}")
