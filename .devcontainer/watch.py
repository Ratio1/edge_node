#!/usr/bin/env python3
"""
Development file watcher for Edge Node hot reload.

Watches for Python file changes in extensions/ and plugins/ directories,
then automatically restarts the edge node process.

Usage:
    python .devcontainer/dev_watch.py

Options:
    --no-initial    Don't start the process immediately, wait for first change
    --debounce N    Seconds to wait before restarting (default: 1.0)
"""
import subprocess
import sys
import time
import os
import signal
import argparse
from pathlib import Path

try:
  from watchdog.observers import Observer
  from watchdog.events import PatternMatchingEventHandler
except ImportError:
  print("Installing watchdog...")
  subprocess.check_call([sys.executable, "-m", "pip", "install", "watchdog", "-q"])
  from watchdog.observers import Observer
  from watchdog.events import PatternMatchingEventHandler


class EdgeNodeReloader(PatternMatchingEventHandler):
  """Handles file changes and restarts the edge node process."""

  def __init__(self, debounce_seconds=1.0):
    super().__init__(
      patterns=["*.py"],
      ignore_patterns=["*/__pycache__/*", "*/.git/*", "*/_local_cache/*"],
      ignore_directories=True,
      case_sensitive=True,
    )
    self.process = None
    self.last_restart = 0
    self.debounce_seconds = debounce_seconds
    self.restart_pending = False

  def start_process(self):
    """Start or restart the edge node process."""
    self.stop_process()

    print("\n" + "=" * 60)
    print("  Starting edge node...")
    print("=" * 60 + "\n")

    self.process = subprocess.Popen(
      [sys.executable, "device.py"],
      cwd="/edge_node",
      preexec_fn=os.setsid,
    )
    self.last_restart = time.time()
    self.restart_pending = False

  def stop_process(self):
    """Stop the running edge node process and all its children."""
    if self.process and self.process.poll() is None:
      pgid = os.getpgid(self.process.pid)
      print("\n  Stopping edge node (PID: {}, PGID: {})...".format(self.process.pid, pgid))
      os.killpg(pgid, signal.SIGTERM)
      try:
        self.process.wait(timeout=10)
      except subprocess.TimeoutExpired:
        print("  Force killing process group...")
        os.killpg(pgid, signal.SIGKILL)
        self.process.wait()
      print("  Stopped.")

  def _should_restart(self):
    """Check if enough time has passed since last restart."""
    return time.time() - self.last_restart >= self.debounce_seconds

  def _trigger_restart(self, event_path):
    """Handle a file change event."""
    if not self._should_restart():
      self.restart_pending = True
      return

    # Get relative path for cleaner output
    try:
      rel_path = Path(event_path).relative_to("/edge_node")
    except ValueError:
      rel_path = event_path

    print("\n  File changed: {}".format(rel_path))
    self.start_process()

  def on_modified(self, event):
    self._trigger_restart(event.src_path)

  def on_created(self, event):
    self._trigger_restart(event.src_path)

  def on_moved(self, event):
    self._trigger_restart(event.dest_path)

  def check_pending_restart(self):
    """Check and execute pending restart if debounce period passed."""
    if self.restart_pending and self._should_restart():
      print("\n  Executing pending restart...")
      self.start_process()


def main():
  parser = argparse.ArgumentParser(description="Edge Node development watcher")
  parser.add_argument("--no-initial", action="store_true", help="Don't start immediately")
  parser.add_argument("--debounce", type=float, default=1.0, help="Debounce seconds")
  args = parser.parse_args()

  # Directories to watch
  watch_dirs = [
    "/edge_node/extensions",
    "/edge_node/plugins",
  ]

  # Also watch single files
  watch_files = [
    "/edge_node/constants.py",
    "/edge_node/device.py",
  ]

  handler = EdgeNodeReloader(debounce_seconds=args.debounce)
  observer = Observer()

  print("\n" + "=" * 60)
  print("  Edge Node Development Watcher")
  print("=" * 60)
  print("\n  Watching for changes in:")

  for dir_path in watch_dirs:
    path = Path(dir_path)
    if path.exists():
      observer.schedule(handler, str(path), recursive=True)
      print("    - {}/**/*.py".format(path.name))

  # Watch parent directory for single files
  observer.schedule(handler, "/edge_node", recursive=False)
  print("    - constants.py, device.py")

  print("\n  Press Ctrl+C to stop.\n")

  # Handle graceful shutdown
  def signal_handler(signum, frame):
    print("\n\n  Shutting down...")
    handler.stop_process()
    observer.stop()
    sys.exit(0)

  signal.signal(signal.SIGINT, signal_handler)
  signal.signal(signal.SIGTERM, signal_handler)

  observer.start()

  # Start the process initially unless --no-initial
  if not args.no_initial:
    handler.start_process()

  # Main loop - check for pending restarts
  try:
    while True:
      time.sleep(0.5)
      handler.check_pending_restart()

      # Check if process died unexpectedly
      if handler.process and handler.process.poll() is not None:
        exit_code = handler.process.returncode
        if exit_code != 0:
          print("\n  Process exited with code {}. Waiting for file changes...".format(exit_code))
          handler.process = None
  except KeyboardInterrupt:
    pass
  finally:
    handler.stop_process()
    observer.stop()
    observer.join()


if __name__ == "__main__":
  main()
