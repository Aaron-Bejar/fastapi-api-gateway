import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SERVICES = (
    ("products", "services.products.main:app", 8001),
    ("orders", "services.orders.main:app", 8002),
    ("users", "services.users.main:app", 8003),
    ("gateway", "gateway.main:app", 8000),
)


def stop_processes(processes):
    for _, process in processes:
        if process.poll() is None:
            try:
                process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
            except ProcessLookupError:
                pass

    for name, process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print(f"Forcing {name} to stop...", flush=True)
            process.kill()
            process.wait()


def main():
    processes = []
    try:
        for name, app, port in SERVICES:
            print(f"Starting {name} on port {port}...", flush=True)
            process = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", app, "--port", str(port)],
                cwd=ROOT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
            processes.append((name, process))

        print("Press Ctrl+C to stop all services.", flush=True)
        while True:
            for name, process in processes:
                if process.poll() is not None:
                    print(f"{name} exited with code {process.returncode}; stopping all services.", flush=True)
                    return 1
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nStopping all services...", flush=True)
        return 0
    finally:
        stop_processes(processes)


if __name__ == "__main__":
    sys.exit(main())
