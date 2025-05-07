import json
import logging
import os
import smtplib
import socket
import time
from datetime import datetime
from email.mime.text import MIMEText

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    USE_WATCHDOG = True
except ImportError:
    USE_WATCHDOG = False
    # Logging will be set up later, so print for now
    print("Warning: 'watchdog' library not found. Falling back to polling.")
    print("Install with: pip install watchdog")

# Attempt to import requests for Slack, optional
try:
    import requests

    SLACK_ENABLED_GLOBALLY = True
except ImportError:
    SLACK_ENABLED_GLOBALLY = False
    print(
        "Warning: 'requests' library not found. Slack notifications will be disabled."
    )
    print("Install with: pip install requests")

# --- Logging Setup ---
LOG_FILE_NAME = "notifier.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s"
)

ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

try:
    fh = logging.FileHandler(LOG_FILE_NAME, mode="a")  # Append mode
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    # Can't use logging.info yet if basicConfig hasn't run implicitly, but logger.addHandler is fine.
    # We will log this confirmation after basicConfig or equivalent setup.
except Exception as e:
    # Use print because logging might not be fully set up to file yet.
    print(f"Critical Error: Failed to set up file logging to {LOG_FILE_NAME}: {e}")
    print("Logging to console only.")
# --- End Logging Setup ---


CONFIG_FILE = "config.json"
g_config = None  # Initialize global config
g_reported_crashes = set()
g_last_config_mtime = 0
g_active_observers = {}  # For watchdog mode: maps crash_dir to observer instance


def load_config_from_file():
    global g_config, g_last_config_mtime
    try:
        with open(CONFIG_FILE, "r") as f:
            new_config = json.load(f)
        g_config = new_config  # Assign to global
        g_last_config_mtime = os.path.getmtime(CONFIG_FILE)
        logging.info(f"Configuration (re)loaded from {CONFIG_FILE}")
        return True
    except FileNotFoundError:
        logging.error(f"Configuration file '{CONFIG_FILE}' not found.")
        return False
    except json.JSONDecodeError as e:
        logging.error(
            f"Could not decode JSON from '{CONFIG_FILE}': {e}. Please check its syntax."
        )
        return False
    except Exception as e:
        logging.error(f"Unexpected error loading config: {e}")
        return False


def load_reported_crashes():
    global g_reported_crashes
    reported_file_path = "reported_crashes.txt"
    if g_config and isinstance(g_config, dict) and "reported_crashes_file" in g_config:
        config_path = g_config.get("reported_crashes_file")
        if isinstance(config_path, str) and config_path.strip():
            reported_file_path = config_path.strip()
        elif config_path is not None:
            logging.warning(
                f"Invalid 'reported_crashes_file' in config. Using default: {reported_file_path}"
            )

    if os.path.exists(reported_file_path):
        try:
            with open(reported_file_path, "r") as f:
                g_reported_crashes = {line.strip() for line in f if line.strip()}
            logging.info(
                f"Loaded {len(g_reported_crashes)} reported crashes from {reported_file_path}"
            )
        except IOError as e:
            logging.error(
                f"Could not read reported crashes file {reported_file_path}: {e}"
            )
    else:
        logging.info(
            f"No existing reported crashes file found at {reported_file_path}. Will create if needed."
        )


def save_reported_crash(crash_id):
    global g_reported_crashes
    reported_file_path = "reported_crashes.txt"
    if g_config and isinstance(g_config, dict) and "reported_crashes_file" in g_config:
        config_path = g_config.get("reported_crashes_file")
        if isinstance(config_path, str) and config_path.strip():
            reported_file_path = config_path.strip()
        elif config_path is not None:
            logging.warning(
                f"Invalid 'reported_crashes_file' in config during save. Using default: {reported_file_path}"
            )

    g_reported_crashes.add(crash_id)
    try:
        with open(reported_file_path, "a") as f:
            f.write(crash_id + "\n")
    except IOError as e:
        logging.error(
            f"Could not write to reported crashes file {reported_file_path}: {e}"
        )


def send_email_notification(
    fuzzer_name,
    timestamp_str,
    reproducer_name,
    reproducer_path,
    file_size_str,
    content_snippet,
):
    if not g_config:
        logging.error("Cannot send email: Global config not loaded.")
        return
    email_conf = g_config.get("notifiers", {}).get("email", {})
    if not email_conf.get("enabled"):
        return

    subject = f"New Crash Found by {fuzzer_name}: {reproducer_name}"
    body_lines = [
        f"Fuzzer: {fuzzer_name}",
        f"Timestamp: {timestamp_str}",
        f"Reproducer: {reproducer_name}",
        f"Path: {reproducer_path}",
        f"Size: {file_size_str}",
    ]
    if content_snippet:
        body_lines.append(f"\nContent Snippet:\n---\n{content_snippet}\n---")
    body_lines.append("\nPlease investigate.")

    body = "\n".join(body_lines)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = email_conf.get("smtp_user", "notifier@example.com")
    msg["To"] = email_conf.get("recipient_email", "devnull@example.com")

    try:
        with smtplib.SMTP(email_conf["smtp_server"], email_conf["smtp_port"]) as server:
            server.starttls()
            server.login(email_conf["smtp_user"], email_conf["smtp_password"])
            server.sendmail(
                email_conf["smtp_user"],
                [email_conf["recipient_email"]],
                msg.as_string(),
            )
        logging.info(f"Email notification sent for {reproducer_name}")
    except Exception as e:
        logging.error(f"Failed to send email for {reproducer_name}: {e}")


def get_file_snippet(
    file_path,
    format_type="hexdump",  # Default to hexdump
    max_hexdump_bytes=64,  # Total bytes for hexdump
    hexdump_bytes_per_line=16,  # Bytes per line for hexdump
    max_text_lines=5,  # For text format
    max_bytes_per_text_line=100,
    max_total_text_bytes=1024,
):  # Max total for text snippet
    if not os.path.exists(file_path):
        return "[File not found for snippet]"

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return "[Empty file]"

    if format_type == "hexdump":
        try:
            with open(file_path, "rb") as f:
                # Read only up to max_hexdump_bytes or file_size, whichever is smaller
                bytes_to_read = min(file_size, max_hexdump_bytes)
                data_to_dump = f.read(bytes_to_read)
            if not data_to_dump:
                return "[Empty file (read 0 bytes)]"  # Should be caught by size check

            # Call our new hexdump formatter
            return format_bytes_as_hexdump(
                data_to_dump, bytes_per_line=hexdump_bytes_per_line
            )
        except Exception as e:
            logging.warning(f"Could not read file for hexdump {file_path}: {e}")
            return "[Error reading file for hexdump]"

    elif format_type == "text":
        # (Keep your existing text snippet logic here)
        snippet_lines = []
        total_bytes_read = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line_text in enumerate(f):
                    if i >= max_text_lines:
                        snippet_lines.append("... (more lines)")
                        break
                    truncated_line = line_text.rstrip("\n")
                    # Truncate long lines based on estimated byte length
                    if (
                        len(truncated_line.encode("utf-8", "ignore"))
                        > max_bytes_per_text_line
                    ):
                        char_limit = max_bytes_per_text_line
                        temp_line = truncated_line
                        while (
                            len(temp_line[:char_limit].encode("utf-8", "ignore"))
                            > max_bytes_per_text_line
                            and char_limit > 0
                        ):
                            char_limit -= 1
                        truncated_line = temp_line[:char_limit] + "..."
                    snippet_lines.append(truncated_line)

                    total_bytes_read += len(line_text.encode("utf-8", "ignore"))
                    if (
                        total_bytes_read > max_total_text_bytes
                    ):  # Prevent reading too much for text snippet
                        if i < max_text_lines - 1:
                            snippet_lines.append("... (max snippet size reached)")
                        break
            if not snippet_lines:
                return "[Empty or non-text file snippet]"
            return "\n".join(snippet_lines)
        except Exception as e:
            logging.debug(f"Could not read text snippet from {file_path}: {e}")
            return "[Could not read file content as text]"
    else:
        logging.warning(f"Unknown snippet format type: {format_type}")
        return "[Unknown snippet format type]"


def send_slack_notification(
    fuzzer_name,
    timestamp_str,
    reproducer_name,
    reproducer_path,
    file_size_str,
    content_snippet,
):
    if not g_config:
        logging.error("Cannot send Slack message: Global config not loaded.")
        return

    slack_conf = g_config.get("notifiers", {}).get("slack", {})
    slack_msg_opts = g_config.get(
        "slack_message_options", {}
    )  # Default to empty dict if not present

    if not slack_conf.get("enabled") or not SLACK_ENABLED_GLOBALLY:
        if not SLACK_ENABLED_GLOBALLY and slack_conf.get("enabled"):
            logging.warning("Slack configured but 'requests' library missing.")
        return

    webhook_url = slack_conf.get("webhook_url")
    if not webhook_url:
        logging.error("Slack webhook URL not configured.")
        return

    # Construct the simple text message for fallback and notifications
    text_message_parts = [
        f"New Crash Found by {fuzzer_name}!",
        f"Reproducer: {reproducer_name}",
        f"Size: {file_size_str}",
        f"Timestamp: {timestamp_str}",
    ]
    if slack_msg_opts.get("include_hostname", True):
        try:
            hostname = socket.gethostname()
            text_message_parts.append(f"Host: {hostname}")
        except Exception:
            pass  # Don't break notification for this

    text_message = " | ".join(text_message_parts)  # A concise version for notifications

    # Construct Block Kit payload
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":boom: New Crash Found!",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Fuzzer:*\n{fuzzer_name}"},
                {"type": "mrkdwn", "text": f"*Timestamp:*\n{timestamp_str}"},
                {"type": "mrkdwn", "text": f"*Reproducer:*\n`{reproducer_name}`"},
                {"type": "mrkdwn", "text": f"*Size:*\n{file_size_str}"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Path:*\n`{reproducer_path}`"},
        },
    ]

    if slack_msg_opts.get("include_hostname", True):
        try:
            hostname = socket.gethostname()
            # Add to the fields array if it exists, otherwise create a new section
            if (
                len(blocks[1].get("fields", [])) < 10
            ):  # Slack limits fields in a section
                blocks[1]["fields"].append(
                    {"type": "mrkdwn", "text": f"*Host:*\n{hostname}"}
                )
            else:  # Add as a new section if fields are full or structure changed
                blocks.append(
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Host:*\n{hostname}"},
                    }
                )
        except Exception as e:
            logging.warning(f"Could not retrieve hostname for Slack: {e}")
            if len(blocks[1].get("fields", [])) < 10:
                blocks[1]["fields"].append(
                    {"type": "mrkdwn", "text": "*Host:*\nUnknown"}
                )
            else:
                blocks.append(
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "*Host:*\nUnknown"},
                    }
                )

    if slack_msg_opts.get("show_content_snippet", True) and content_snippet:
        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Content Snippet:*\n```\n{content_snippet}\n```",
                },
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Sent by Fuzzing Notifier at {datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}",
                }
            ],
        }
    )

    payload = {
        "text": text_message,  # Fallback text and for push notifications
        "blocks": blocks,
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        logging.info(f"Slack notification sent for {reproducer_name} (using Block Kit)")
    except requests.exceptions.RequestException as e:
        logging.error(
            f"Failed to send Slack message (Block Kit) for {reproducer_name}: {e}"
        )


def process_new_crash(fuzzer_config, file_path):
    file_name = os.path.basename(file_path)
    fuzzer_name = fuzzer_config.get("name", "UnknownFuzzer")
    crash_id = f"{fuzzer_name}::{file_name}"

    if crash_id in g_reported_crashes:
        return

    logging.info(
        f"New potential crash found by {fuzzer_name}: {file_name} at {file_path}"
    )

    timestamp_str = "N/A"
    file_size_str = "N/A"
    content_snippet = ""

    try:
        stat_info = os.stat(file_path)
        timestamp = getattr(stat_info, "st_birthtime", stat_info.st_mtime)
        timestamp_dt = datetime.fromtimestamp(timestamp)
        timestamp_str = timestamp_dt.strftime("%Y-%m-%d %H:%M:%S")

        file_size = stat_info.st_size
        if file_size < 1024:
            file_size_str = f"{file_size} B"
        elif file_size < 1024 * 1024:
            file_size_str = f"{file_size / 1024:.1f} KB"
        else:
            file_size_str = f"{file_size / (1024 * 1024):.1f} MB"

        # Get content snippet if configured
        content_snippet = "[Snippet not generated]"  # Default
        if g_config and isinstance(g_config, dict):
            # Shared message options or specific to Slack/Email
            msg_opts = g_config.get(
                "slack_message_options", {}
            )  # Or a general "message_options"

            if msg_opts.get("show_content_snippet", True):
                snippet_format = msg_opts.get(
                    "content_snippet_format", "hexdump"
                )  # Default to hexdump

                # Hexdump specific config
                hexdump_total_bytes = msg_opts.get("content_snippet_hexdump_bytes", 64)
                hexdump_bpl = msg_opts.get("content_snippet_hexdump_bytes_per_line", 16)

                # Text specific config (for fallback or if "text" is chosen)
                text_max_lines = msg_opts.get("content_snippet_max_lines", 5)
                text_max_bpl = msg_opts.get("content_snippet_max_bytes_per_line", 100)
                text_max_total_bytes = msg_opts.get(
                    "content_snippet_text_max_total_bytes", 1024
                )

                content_snippet = get_file_snippet(
                    file_path,
                    format_type=snippet_format,
                    max_hexdump_bytes=hexdump_total_bytes,
                    hexdump_bytes_per_line=hexdump_bpl,
                    max_text_lines=text_max_lines,
                    max_bytes_per_text_line=text_max_bpl,
                    max_total_text_bytes=text_max_total_bytes,  # Pass this to text mode
                )

    except Exception as e:
        logging.warning(f"Could not get all file metadata for {file_path}: {e}")
        # timestamp_str and file_size_str will keep their "N/A" or last good value

    send_email_notification(
        fuzzer_name, timestamp_str, file_name, file_path, file_size_str, content_snippet
    )
    send_slack_notification(
        fuzzer_name, timestamp_str, file_name, file_path, file_size_str, content_snippet
    )
    save_reported_crash(crash_id)


def format_bytes_as_hexdump(data_bytes, bytes_per_line=16):
    """
    Formats a bytes object into a hexdump -C like string.
    """
    if not data_bytes:
        return "[No data to hexdump]"
    if bytes_per_line <= 0:  # Safety check
        bytes_per_line = 16

    lines = []
    # Prepare a filter for printable ASCII characters, using '.' for others.
    PRINTABLE_CHARS = "".join([(chr(x) if 32 <= x <= 126 else ".") for x in range(256)])

    for offset in range(0, len(data_bytes), bytes_per_line):
        chunk = data_bytes[offset : offset + bytes_per_line]

        # 1. Offset part
        # line_str = f"{offset:08x}: " # Initial part of the line

        # 2. Hex part
        # Construct hex string with a double space in the middle if bytes_per_line is suitable
        hex_parts = []
        midpoint = bytes_per_line // 2
        for i in range(bytes_per_line):
            if i < len(chunk):
                hex_parts.append(f"{chunk[i]:02x}")
            else:
                hex_parts.append("  ")  # Pad with two spaces if byte not present
            if (
                i == midpoint - 1 and bytes_per_line > 4
            ):  # Add double space after midpoint (if not too small line)
                hex_parts.append(
                    ""
                )  # This effectively adds an extra space when joining by ' '

        hex_part_str = " ".join(hex_parts)

        # Calculate the display width for the hex string to ensure alignment.
        # Each byte takes 2 chars + 1 space = 3. Total = bytes_per_line * 3.
        # If there's a midpoint double space, add 1.
        hex_display_width = (bytes_per_line * 3) - 1  # (xx_xx_xx -> 2*N + (N-1) spaces)
        if (
            bytes_per_line > 4 and midpoint > 0
        ):  # Account for the extra space at midpoint
            hex_display_width += 1

        # 3. ASCII part
        ascii_part = "".join([PRINTABLE_CHARS[b] for b in chunk])

        # Combine, ensuring hex part is padded for alignment
        # The offset is 8 chars + ":  " (3 chars) = 11 chars prefix
        lines.append(
            f"{offset:08x}:  {hex_part_str:<{hex_display_width}} |{ascii_part}|"
        )

    return "\n".join(lines)


# --- Watchdog Handler & Management ---
if USE_WATCHDOG:

    class CrashWatchdogHandler(FileSystemEventHandler):
        def __init__(self, fuzzer_config_ref):
            self.fuzzer_config = fuzzer_config_ref
            super().__init__()

        def on_created(self, event):
            if event.is_directory:
                return
            settle_delay = 0.5  # Default
            if g_config and isinstance(g_config, dict):
                settle_delay = (
                    g_config.get("watchdog_file_settle_delay_ms", 500) / 1000.0
                )
            time.sleep(settle_delay)
            logging.debug(
                f"Watchdog event: created {event.src_path} for {self.fuzzer_config['name']}"
            )
            process_new_crash(self.fuzzer_config, event.src_path)


def manage_watchdog_observers():
    global g_active_observers, g_config

    # Stop all current observers
    for crash_dir, observer_instance in list(g_active_observers.items()):
        try:
            observer_instance.stop()
            observer_instance.join(timeout=5)
            if observer_instance.is_alive():
                logging.warning(
                    f"Observer thread for {crash_dir} did not stop in time."
                )
            else:
                logging.info(f"Stopped watching {crash_dir}")
        except Exception as e:
            logging.error(f"Error stopping observer for {crash_dir}: {e}")
        if (
            crash_dir in g_active_observers
        ):  # Check because it might be deleted by another thread if error
            del g_active_observers[crash_dir]

    g_active_observers.clear()

    if not g_config:
        logging.error("Cannot manage watchdog observers: Global config not loaded.")
        return

    fuzzers_to_watch = g_config.get("fuzzers_to_watch", [])
    if not fuzzers_to_watch:
        logging.info(
            "No fuzzers configured in 'fuzzers_to_watch' to start observers for."
        )
        return

    for fuzzer_conf in fuzzers_to_watch:
        crash_dir = fuzzer_conf.get("crash_dir")
        fuzzer_name = fuzzer_conf.get("name", "UnnamedFuzzer")
        if not crash_dir:
            logging.warning(
                f"Fuzzer '{fuzzer_name}' has no 'crash_dir' configured. Skipping."
            )
            continue

        if not os.path.isdir(crash_dir):
            logging.warning(
                f"Crash directory for {fuzzer_name} not found: {crash_dir}. Skipping watchdog."
            )
            continue

        if crash_dir in g_active_observers:
            logging.warning(
                f"Observer for {crash_dir} ({fuzzer_name}) appears to be already managed. Skipping duplicate setup."
            )
            continue

        event_handler = CrashWatchdogHandler(fuzzer_conf)
        observer = Observer()
        observer.schedule(event_handler, crash_dir, recursive=False)
        try:
            observer.start()
            g_active_observers[crash_dir] = observer
            logging.info(f"Watching for crashes in {crash_dir} for {fuzzer_name}")
        except Exception as e:
            logging.error(
                f"Failed to start observer for {crash_dir} ({fuzzer_name}): {e}"
            )

    if (
        not g_active_observers and fuzzers_to_watch
    ):  # If there were configs, but none resulted in an observer
        logging.warning(
            "Watchdog mode: No valid/accessible directories are being watched after (re)configuration."
        )


# --- Polling Mode ---
def poll_directories():
    logging.info("Starting directory polling with hot-reload support...")

    last_poll_time = 0
    last_config_check_time = time.time()
    logged_no_fuzzers_ts = 0

    while True:
        if not g_config:  # Should ideally not happen after initial load
            logging.error("Polling critical error: g_config is None. Trying to reload.")
            if not load_config_from_file():
                logging.error("Reload failed in polling loop. Sleeping before retry.")
                time.sleep(60)  # Prevent tight loop on persistent config error
                continue

        config_check_interval = g_config.get("config_check_interval_seconds", 60)
        crash_poll_interval = g_config.get("check_interval_seconds", 10)
        now = time.time()

        # 1. Check for config changes
        if now - last_config_check_time >= config_check_interval:
            last_config_check_time = now
            current_mtime = 0
            config_exists = os.path.exists(CONFIG_FILE)
            if config_exists:
                try:
                    current_mtime = os.path.getmtime(CONFIG_FILE)
                except OSError as e:
                    logging.warning(
                        f"Could not get mtime for {CONFIG_FILE}: {e}. Config will not be reloaded based on mtime."
                    )
                    config_exists = False  # Treat as if not found for mtime check

            if (config_exists and current_mtime > g_last_config_mtime) or (
                g_last_config_mtime == 0 and config_exists
            ):
                logging.info(
                    f"Configuration file {CONFIG_FILE} change detected or initial load pending. Reloading..."
                )
                if load_config_from_file():
                    logging.info("Configuration reloaded for polling mode.")
                    # Intervals might have changed, will be picked up at start of next loop
                else:
                    logging.warning(
                        "Failed to reload config in polling mode. Continuing with old/default config."
                    )
            elif (
                not config_exists and g_last_config_mtime != 0
            ):  # Was loaded, now missing
                logging.warning(
                    f"Config file {CONFIG_FILE} was present but now missing. Using last known config."
                )

        # 2. Poll for crashes
        if now - last_poll_time >= crash_poll_interval:
            last_poll_time = now
            current_fuzzer_configs = g_config.get("fuzzers_to_watch", [])

            if not current_fuzzer_configs:
                if now - logged_no_fuzzers_ts > 300:  # Log every 5 mins
                    logging.info("Polling: No fuzzers configured to watch.")
                    logged_no_fuzzers_ts = now

            for fuzzer_conf in current_fuzzer_configs:
                crash_dir = fuzzer_conf.get("crash_dir")
                fuzzer_name = fuzzer_conf.get("name", "UnnamedFuzzer")
                if not crash_dir:
                    # This should have been logged by manage_watchdog_observers or if fuzzer_conf is malformed
                    continue

                if not os.path.isdir(crash_dir):
                    if (
                        not fuzzer_conf.get("_logged_missing_dir_ts")
                        or now - fuzzer_conf["_logged_missing_dir_ts"] > 300
                    ):
                        logging.warning(
                            f"Polling: Crash directory for {fuzzer_name} not found: {crash_dir}"
                        )
                        fuzzer_conf["_logged_missing_dir_ts"] = now  # Mark as logged
                    continue
                fuzzer_conf["_logged_missing_dir_ts"] = 0  # Reset if found

                try:
                    for item in os.listdir(crash_dir):
                        item_path = os.path.join(crash_dir, item)
                        if os.path.isfile(item_path):
                            # Basic filtering for common non-crash files
                            if item in {
                                ".state",
                                "fuzzer_stats",
                                "README.txt",
                            } or item.endswith((".synced", ".DS_Store")):
                                continue
                            process_new_crash(fuzzer_conf, item_path)
                except Exception as e:
                    logging.error(
                        f"Polling: Error scanning directory {crash_dir} for {fuzzer_name}: {e}"
                    )

        next_event_time = min(
            last_config_check_time + config_check_interval,
            last_poll_time + crash_poll_interval,
        )
        sleep_duration = max(0.1, next_event_time - time.time())  # Sleep at least 0.1s
        time.sleep(sleep_duration)


# --- Main ---
def main():
    global g_config  # For assignment in case of initial load failure

    logging.info(
        f"Notifier starting up. PID: {os.getpid()}. Watchdog mode: {USE_WATCHDOG}"
    )
    if fh:
        logging.info(f"Logging to console and {LOG_FILE_NAME}")
    else:
        logging.info("Logging to console only (file logging setup failed).")

    if not load_config_from_file():
        logging.warning(
            "Initial configuration load failed. Some features might be unavailable or use defaults."
        )
        if g_config is None:
            g_config = {}
            logging.info("Initialized g_config to empty dict as initial load failed.")

    load_reported_crashes()

    if USE_WATCHDOG:
        logging.info("Initializing watchdog observers...")
        manage_watchdog_observers()

        if not g_active_observers and g_config.get("fuzzers_to_watch"):
            logging.warning(
                "Watchdog: No observers started despite configured fuzzers. Check paths/permissions."
            )
        elif not g_config.get("fuzzers_to_watch"):
            logging.info("Watchdog: No fuzzers configured to watch initially.")

        try:
            while True:
                config_check_interval = (
                    g_config.get("config_check_interval_seconds", 60)
                    if g_config
                    else 60
                )
                time.sleep(config_check_interval)

                current_mtime = 0
                config_exists = os.path.exists(CONFIG_FILE)
                if config_exists:
                    try:
                        current_mtime = os.path.getmtime(CONFIG_FILE)
                    except OSError as e:
                        logging.warning(
                            f"Could not get mtime for {CONFIG_FILE}: {e}. Config will not be reloaded."
                        )
                        config_exists = False

                # Reload if (exists AND changed) OR (was never loaded AND now exists)
                if (config_exists and current_mtime > g_last_config_mtime) or (
                    g_last_config_mtime == 0
                    and config_exists
                    and not g_config.get("fuzzers_to_watch")
                ):
                    logging.info(
                        f"Config file {CONFIG_FILE} change detected or initial load pending. Reloading..."
                    )
                    if load_config_from_file():
                        manage_watchdog_observers()
                    else:
                        logging.error(
                            "Failed to reload configuration in watchdog mode. Observers may be outdated."
                        )
                elif (
                    not config_exists and g_last_config_mtime != 0
                ):  # If config was there and now isn't
                    logging.warning(
                        f"Config file {CONFIG_FILE} was present but now missing. Using last known config for watchdog."
                    )
        except KeyboardInterrupt:
            logging.info(
                "KeyboardInterrupt received. Shutting down watchdog observers..."
            )
        finally:
            logging.info("Stopping all watchdog observers...")
            # Gracefully stop observers (same as your existing finally block)
            for crash_dir, observer_instance in list(g_active_observers.items()):
                try:
                    observer_instance.stop()
                    observer_instance.join(timeout=2)
                except Exception as e:
                    logging.error(
                        f"Error stopping observer for {crash_dir} on exit: {e}"
                    )
            logging.info("All watchdog observers stopped. Exiting.")
    else:
        poll_directories()  # Ensure poll_directories also uses g_config for intervals correctly


if __name__ == "__main__":
    main()
