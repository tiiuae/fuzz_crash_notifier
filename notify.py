import hashlib
import json
import logging
import os
import smtplib
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Set

# --- Optional Imports & Global Flags ---
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    USE_WATCHDOG = True
except ImportError:
    USE_WATCHDOG = False
    print("Warning: 'watchdog' library not found. Install with: pip install watchdog")

try:
    import requests

    SLACK_ENABLED_GLOBALLY = True
except ImportError:
    SLACK_ENABLED_GLOBALLY = False
    print("Warning: 'requests' library not found. Install with: pip install requests")

# --- Constants ---
CONFIG_FILE_PATH_DEFAULT = "config.json"
REPORTED_UNIQUE_CRASHES_FILE_DEFAULT = "reported_unique_crashes.txt"
LOG_FILE_NAME_DEFAULT = "notifier.log"


# --- Logging Setup ---
# (This function will be called early in the App class)
def setup_logging(
    log_file_name: str = LOG_FILE_NAME_DEFAULT, level: int = logging.INFO
) -> logging.Logger:
    logger_instance = logging.getLogger(__name__)  # Use a named logger
    logger_instance.setLevel(level)
    # Prevent duplicate handlers if called multiple times
    if logger_instance.hasHandlers():
        logger_instance.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s"
    )

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger_instance.addHandler(ch)

    try:
        fh = logging.FileHandler(log_file_name, mode="a")
        fh.setFormatter(formatter)
        logger_instance.addHandler(fh)
        print(f"Logging to console and {log_file_name}")
    except Exception as e:
        print(
            f"Critical Error: Failed to set up file logging to {log_file_name}: {e}. Logging to console only."
        )
    return logger_instance


# Global logger instance, configured by setup_logging
logger = setup_logging()


# --- Data Structures ---
@dataclass
class CrashData:
    fuzzer_name: str
    timestamp_str: str
    reproducer_name: str
    reproducer_path: str
    file_size_str: str
    content_snippet: str
    file_hashes: Dict[str, str]
    hostname: str = field(default_factory=socket.gethostname)


@dataclass
class FuzzerConfig:
    name: str
    crash_dir: str
    # NOTE: Add other fuzzer-specific config here


# --- Configuration Management ---
class ConfigManager:
    def __init__(self, config_path: str = CONFIG_FILE_PATH_DEFAULT):
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.last_mtime: float = 0
        self.load_config()

    def load_config(self) -> bool:
        try:
            with open(self.config_path, "r") as f:
                self.config = json.load(f)
            self.last_mtime = os.path.getmtime(self.config_path)
            logger.info(f"Configuration (re)loaded from {self.config_path}")
            return True
        except FileNotFoundError:
            logger.error(f"Configuration file '{self.config_path}' not found.")
            self.config = {}  # Ensure config is an empty dict, not None
            return False
        except json.JSONDecodeError as e:
            logger.error(f"Could not decode JSON from '{self.config_path}': {e}.")
            return False
        except Exception as e:
            logger.error(f"Unexpected error loading config: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    def get_fuzzers_to_watch(self) -> List[FuzzerConfig]:
        fuzzer_configs = []
        for f_conf in self.config.get("fuzzers_to_watch", []):
            if "name" in f_conf and "crash_dir" in f_conf:
                fuzzer_configs.append(
                    FuzzerConfig(name=f_conf["name"], crash_dir=f_conf["crash_dir"])
                )
            else:
                logger.warning(
                    f"Invalid fuzzer config entry, missing name or crash_dir: {f_conf}"
                )
        return fuzzer_configs

    def needs_reload(self) -> bool:
        if not os.path.exists(self.config_path):
            if self.last_mtime != 0:  # It existed before
                logger.warning(
                    f"Config file {self.config_path} missing. Using last loaded config."
                )
            return False  # Don't try to reload if missing
        try:
            current_mtime = os.path.getmtime(self.config_path)
            if current_mtime > self.last_mtime:
                return True
        except OSError as e:
            logger.warning(f"Could not get mtime for {self.config_path}: {e}")
        return False


# --- State Management (Reported Crashes) ---
class StateManager:
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.reported_unique_crash_ids: Set[str] = set()
        self._filepath: Optional[str] = None
        self.load_state()

    @property
    def filepath(self) -> str:
        if self._filepath is None:  # Cache the path
            self._filepath = self.config_manager.get(
                "reported_unique_crashes_file", REPORTED_UNIQUE_CRASHES_FILE_DEFAULT
            )
        return self._filepath

    def load_state(self) -> None:
        self.reported_unique_crash_ids.clear()
        # Update filepath in case config changed it.
        self._filepath = self.config_manager.get(
            "reported_unique_crashes_file", REPORTED_UNIQUE_CRASHES_FILE_DEFAULT
        )

        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r") as f:
                    self.reported_unique_crash_ids = {
                        line.strip() for line in f if line.strip()
                    }
                logger.info(
                    f"Loaded {len(self.reported_unique_crash_ids)} unique crash IDs from {self.filepath}"
                )
            except IOError as e:
                logger.error(f"Could not read state file {self.filepath}: {e}")
        else:
            logger.info(
                f"No state file found at {self.filepath}. Will create if needed."
            )

    def save_unique_crash_id(self, unique_crash_id: str) -> None:
        self.reported_unique_crash_ids.add(unique_crash_id)
        try:
            with open(self.filepath, "a") as f:
                f.write(unique_crash_id + "\n")
        except IOError as e:
            logger.error(f"Could not write to state file {self.filepath}: {e}")

    def is_unique_crash_reported(self, unique_crash_id: str) -> bool:
        return unique_crash_id in self.reported_unique_crash_ids


# --- File Utilities ---
def calculate_file_hashes(file_path: str) -> Dict[str, str]:
    hashes = {"md5": "N/A", "sha256": "N/A"}
    try:
        with open(file_path, "rb") as f:
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
            hashes["md5"] = md5_hash.hexdigest()
            hashes["sha256"] = sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hashes for {file_path}: {e}")
    return hashes


def format_bytes_as_hexdump(data_bytes: bytes, bytes_per_line: int = 16) -> str:
    # (Your existing, corrected hexdump function)
    if not data_bytes:
        return "[No data to hexdump]"
    if bytes_per_line <= 0:
        bytes_per_line = 16
    lines = []
    PRINTABLE_CHARS = "".join([(chr(x) if 32 <= x <= 126 else ".") for x in range(256)])
    for offset in range(0, len(data_bytes), bytes_per_line):
        chunk = data_bytes[offset : offset + bytes_per_line]
        hex_parts = []
        midpoint = bytes_per_line // 2
        for i in range(bytes_per_line):
            if i < len(chunk):
                hex_parts.append(f"{chunk[i]:02x}")
            else:
                hex_parts.append("  ")
            if i == midpoint - 1 and bytes_per_line > 4:
                hex_parts.append("")
        hex_part_str = " ".join(hex_parts)
        hex_display_width = (bytes_per_line * 3) - 1
        if bytes_per_line > 4 and midpoint > 0:
            hex_display_width += 1
        ascii_part = "".join([PRINTABLE_CHARS[b] for b in chunk])
        lines.append(
            f"{offset:08x}:  {hex_part_str:<{hex_display_width}} |{ascii_part}|"
        )
    return "\n".join(lines)


def get_file_snippet(file_path: str, config_manager: ConfigManager) -> str:
    # (Your existing get_file_snippet, but it takes config_manager to get options)
    if not os.path.exists(file_path):
        return "[File not found for snippet]"
    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return "[Empty file]"

    opts = config_manager.get(
        "slack_message_options", config_manager.get("message_options", {})
    )
    format_type = opts.get("content_snippet_format", "hexdump")

    if format_type == "hexdump":
        max_hexdump_bytes = opts.get("content_snippet_hexdump_bytes", 64)
        hexdump_bpl = opts.get("content_snippet_hexdump_bytes_per_line", 16)
        try:
            with open(file_path, "rb") as f:
                data_to_dump = f.read(min(file_size, max_hexdump_bytes))
            return (
                format_bytes_as_hexdump(data_to_dump, bytes_per_line=hexdump_bpl)
                if data_to_dump
                else "[Empty file]"
            )
        except Exception as e:
            logger.warning(f"Could not read file for hexdump {file_path}: {e}")
            return "[Error reading file for hexdump]"
    elif format_type == "text":
        # (Text snippet logic from previous version)
        max_text_lines = opts.get("content_snippet_max_lines", 5)
        max_bytes_per_text_line = opts.get("content_snippet_max_bytes_per_line", 100)
        max_total_text_bytes = opts.get("content_snippet_text_max_total_bytes", 1024)
        snippet_lines = []
        total_bytes_read = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line_text in enumerate(f):
                    if i >= max_text_lines:
                        snippet_lines.append("... (more lines)")
                        break
                    truncated_line = line_text.rstrip("\n")
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
                    if total_bytes_read > max_total_text_bytes:
                        if i < max_text_lines - 1:
                            snippet_lines.append("... (max snippet size reached)")
                        break
            return (
                "\n".join(snippet_lines)
                if snippet_lines
                else "[Empty or non-text file snippet]"
            )
        except Exception as e:
            logger.debug(f"Could not read text snippet from {file_path}: {e}")
            return "[Could not read file content as text]"
    else:
        logger.warning(f"Unknown snippet format type: {format_type}")
        return "[Unknown snippet format type]"


# --- Notification Services ---
class NotificationService:  # Abstract base class
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", False)

    def send(self, crash_data: CrashData) -> None:
        raise NotImplementedError


class EmailNotifier(NotificationService):
    def send(self, crash_data: CrashData) -> None:
        if not self.enabled:
            return
        logger.debug(f"Attempting to send email for {crash_data.reproducer_name}")
        # (Your existing email sending logic, adapted to use self.config and crash_data)
        subject = (
            f"New Crash Found by {crash_data.fuzzer_name}: {crash_data.reproducer_name}"
        )
        body_lines = [
            f"Fuzzer: {crash_data.fuzzer_name}",
            f"Host: {crash_data.hostname}",
            f"Timestamp: {crash_data.timestamp_str}",
            f"Reproducer: {crash_data.reproducer_name}",
            f"Path: {crash_data.reproducer_path}",
            f"Size: {crash_data.file_size_str}",
            f"MD5: {crash_data.file_hashes.get('md5', 'N/A')}",
            f"SHA256: {crash_data.file_hashes.get('sha256', 'N/A')}",
        ]
        if crash_data.content_snippet:
            body_lines.append(
                f"\nContent Snippet:\n---\n{crash_data.content_snippet}\n---"
            )
        body_lines.append("\nPlease investigate.")
        body = "\n".join(body_lines)
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.config.get("smtp_user", "notifier@example.com")
        msg["To"] = self.config.get("recipient_email", "devnull@example.com")
        try:
            with smtplib.SMTP(
                self.config["smtp_server"], self.config["smtp_port"]
            ) as server:
                server.starttls()
                server.login(self.config["smtp_user"], self.config["smtp_password"])
                server.sendmail(msg["From"], [msg["To"]], msg.as_string())
            logger.info(f"Email notification sent for {crash_data.reproducer_name}")
        except Exception as e:
            logger.error(f"Failed to send email for {crash_data.reproducer_name}: {e}")


class SlackNotifier(NotificationService):
    def __init__(self, config: Dict[str, Any], global_slack_opts: Dict[str, Any]):
        super().__init__(config)
        self.global_slack_opts = (
            global_slack_opts  # e.g., for snippet format from main config
        )
        if self.enabled and not SLACK_ENABLED_GLOBALLY:
            logger.warning(
                "Slack notifier configured as enabled, but 'requests' library is missing."
            )
            self.enabled = False  # Disable if lib is missing

    def send(self, crash_data: CrashData) -> None:
        if not self.enabled:
            return
        logger.debug(
            f"Attempting to send Slack message for {crash_data.reproducer_name}"
        )
        webhook_url = self.config.get("webhook_url")
        if not webhook_url:
            logger.error("Slack webhook URL not configured.")
            return

        text_message_parts = [
            f"New Crash by {crash_data.fuzzer_name}!",
            f"Reproducer: {crash_data.reproducer_name}",
            f"SHA256: {crash_data.file_hashes.get('sha256', 'N/A')[:12]}...",
        ]
        if self.global_slack_opts.get("include_hostname", True):
            text_message_parts.append(f"Host: {crash_data.hostname}")
        text_message = " | ".join(text_message_parts)

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
                    {"type": "mrkdwn", "text": f"*Fuzzer:*\n{crash_data.fuzzer_name}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Timestamp:*\n{crash_data.timestamp_str}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Reproducer:*\n`{crash_data.reproducer_name}`",
                    },
                    {"type": "mrkdwn", "text": f"*Size:*\n{crash_data.file_size_str}"},
                ],
            },
        ]
        if self.global_slack_opts.get("include_hostname", True):
            if len(blocks[1]["fields"]) < 10:
                blocks[1]["fields"].append(
                    {"type": "mrkdwn", "text": f"*Host:*\n{crash_data.hostname}"}
                )
            else:
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Host:*\n{crash_data.hostname}",
                        },
                    }
                )

        blocks.append(
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Path:*\n`{crash_data.reproducer_path}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*MD5:*\n`{crash_data.file_hashes.get('md5', 'N/A')}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*SHA256:*\n`{crash_data.file_hashes.get('sha256', 'N/A')}`",
                    },
                ],
            }
        )
        if (
            self.global_slack_opts.get("show_content_snippet", True)
            and crash_data.content_snippet
        ):
            blocks.extend(
                [
                    {"type": "divider"},
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Content Snippet:*\n```\n{crash_data.content_snippet}\n```",
                        },
                    },
                ]
            )
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Sent by Fuzzer Notifier at {datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}",
                    }
                ],
            }
        )

        payload = {"text": text_message, "blocks": blocks}
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info(f"Slack notification sent for {crash_data.reproducer_name}")
        except requests.exceptions.RequestException as e:
            logger.error(
                f"Failed to send Slack message for {crash_data.reproducer_name}: {e}"
            )


# --- Crash Processing ---
class CrashProcessor:
    def __init__(
        self,
        config_manager: ConfigManager,
        state_manager: StateManager,
        notifiers: List[NotificationService],
    ):
        self.config_manager = config_manager
        self.state_manager = state_manager
        self.notifiers = notifiers

    def process_file(self, fuzzer_conf: FuzzerConfig, file_path: str) -> None:
        file_name = os.path.basename(file_path)
        logger.debug(
            f"Processing potential crash file: {file_path} for fuzzer {fuzzer_conf.name}"
        )

        min_size = self.config_manager.get("min_crash_file_size_bytes", 1)
        try:
            if os.path.getsize(file_path) < min_size:
                logger.debug(f"File {file_name} is too small. Skipping.")
                return
        except OSError:
            logger.warning(f"Could not get size for {file_path}. Skipping.")
            return

        file_hashes = calculate_file_hashes(file_path)
        sha256_hash = file_hashes.get("sha256")

        if not sha256_hash or sha256_hash == "N/A":
            logger.error(
                f"SHA256 hash unavailable for {file_path}. Cannot deduplicate. Skipping."
            )
            return

        unique_crash_id = f"{fuzzer_conf.name}::{sha256_hash}"
        if self.state_manager.is_unique_crash_reported(unique_crash_id):
            logger.info(
                f"Duplicate crash (SHA256: {sha256_hash}) in {file_name} for {fuzzer_conf.name}. Skipping."
            )
            return

        logger.info(
            f"New UNIQUE crash content by {fuzzer_conf.name}: {file_name} (SHA256: {sha256_hash})"
        )

        timestamp_str, file_size_str = "N/A", "N/A"
        try:
            stat_info = os.stat(file_path)
            timestamp = getattr(stat_info, "st_birthtime", stat_info.st_mtime)
            timestamp_str = datetime.fromtimestamp(timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            size = stat_info.st_size
            if size < 1024:
                file_size_str = f"{size} B"
            elif size < 1024 * 1024:
                file_size_str = f"{size / 1024:.1f} KB"
            else:
                file_size_str = f"{size / (1024 * 1024):.1f} MB"
        except FileNotFoundError:
            logger.warning(f"File {file_path} disappeared during processing. Skipping.")
            return
        except Exception as e:
            logger.warning(f"Error getting metadata for {file_path}: {e}")

        content_snippet = get_file_snippet(file_path, self.config_manager)

        crash_data = CrashData(
            fuzzer_name=fuzzer_conf.name,
            timestamp_str=timestamp_str,
            reproducer_name=file_name,
            reproducer_path=file_path,
            file_size_str=file_size_str,
            content_snippet=content_snippet,
            file_hashes=file_hashes,
        )

        for notifier in self.notifiers:
            try:
                notifier.send(crash_data)
            except Exception as e:
                logger.error(
                    f"Error sending notification via {type(notifier).__name__}: {e}"
                )

        self.state_manager.save_unique_crash_id(unique_crash_id)


# --- Directory Monitoring ---
if USE_WATCHDOG:

    class WatchdogCrashHandler(FileSystemEventHandler):
        def __init__(
            self,
            fuzzer_conf: FuzzerConfig,
            processor: CrashProcessor,
            config_manager: ConfigManager,
        ):
            self.fuzzer_conf = fuzzer_conf
            self.processor = processor
            self.config_manager = config_manager
            super().__init__()

        def on_created(self, event: Any) -> None:
            if event.is_directory:
                return
            # Use a settle delay from config
            settle_delay_ms = self.config_manager.get(
                "watchdog_file_settle_delay_ms", 500
            )
            time.sleep(settle_delay_ms / 1000.0)
            logger.debug(
                f"Watchdog: created {event.src_path} for {self.fuzzer_conf.name}"
            )
            self.processor.process_file(self.fuzzer_conf, event.src_path)


class DirectoryMonitor:
    def __init__(self, config_manager: ConfigManager, processor: CrashProcessor):
        self.config_manager = config_manager
        self.processor = processor
        self.active_observers: Dict[str, Observer] = {}  # For watchdog
        self._stop_polling_flag = False  # For polling mode graceful stop

    def start(self) -> None:
        if USE_WATCHDOG:
            self.manage_watchdog_observers()
        else:
            self.poll_directories()  # This will block if not threaded

    def stop(self) -> None:
        if USE_WATCHDOG:
            self._stop_all_watchdog_observers()
        else:
            self._stop_polling_flag = True

    def _stop_all_watchdog_observers(self) -> None:
        logger.info("Stopping all watchdog observers...")
        for crash_dir, observer_instance in list(self.active_observers.items()):
            try:
                observer_instance.stop()
                observer_instance.join(timeout=2)
                logger.info(f"Stopped watching {crash_dir}")
            except Exception as e:
                logger.error(f"Error stopping observer for {crash_dir}: {e}")
            if crash_dir in self.active_observers:
                del self.active_observers[crash_dir]
        self.active_observers.clear()

    def manage_watchdog_observers(self) -> None:
        self._stop_all_watchdog_observers()
        fuzzers = self.config_manager.get_fuzzers_to_watch()
        if not fuzzers:
            logger.info("Watchdog: No fuzzers configured.")
            return

        for f_conf in fuzzers:
            if not os.path.isdir(f_conf.crash_dir):
                logger.warning(
                    f"Watchdog: Crash dir for {f_conf.name} not found: {f_conf.crash_dir}"
                )
                continue
            if f_conf.crash_dir in self.active_observers:
                continue  # Should not happen after clear

            handler = WatchdogCrashHandler(f_conf, self.processor, self.config_manager)
            observer = Observer()
            observer.schedule(handler, f_conf.crash_dir, recursive=False)
            try:
                observer.start()
                self.active_observers[f_conf.crash_dir] = observer
                logger.info(f"Watchdog: Watching {f_conf.crash_dir} for {f_conf.name}")
            except Exception as e:
                logger.error(
                    f"Watchdog: Failed to start observer for {f_conf.crash_dir}: {e}"
                )

        if not self.active_observers and fuzzers:
            logger.warning("Watchdog: No observers started despite configured fuzzers.")

    def poll_directories(self) -> None:  # This is a blocking call
        logger.info("Starting polling mode...")
        self._stop_polling_flag = False
        last_poll_time = 0
        logged_no_fuzzers_ts = 0

        while not self._stop_polling_flag:
            # Config changes are handled by the main app loop,
            # this polling just uses the current config_manager state.
            poll_interval = self.config_manager.get("check_interval_seconds", 10)
            now = time.time()

            if now - last_poll_time >= poll_interval:
                last_poll_time = now
                fuzzers = self.config_manager.get_fuzzers_to_watch()
                if not fuzzers:
                    if now - logged_no_fuzzers_ts > 300:
                        logger.info("Polling: No fuzzers configured.")
                        logged_no_fuzzers_ts = now

                for f_conf in fuzzers:
                    if not os.path.isdir(f_conf.crash_dir):
                        # NOTE: Add periodic logging for missing dir
                        continue
                    try:
                        for item in os.listdir(f_conf.crash_dir):
                            item_path = os.path.join(f_conf.crash_dir, item)
                            if os.path.isfile(item_path):
                                # Basic filtering
                                if item in {
                                    ".state",
                                    "fuzzer_stats",
                                    "README.txt",
                                } or item.endswith((".synced", ".DS_Store")):
                                    continue
                                self.processor.process_file(f_conf, item_path)
                    except Exception as e:
                        logger.error(f"Polling: Error scanning {f_conf.crash_dir}: {e}")

            # Determine sleep duration until next poll
            # Config check is handled by the main app loop
            sleep_duration = max(0.1, (last_poll_time + poll_interval) - time.time())
            time.sleep(sleep_duration)
        logger.info("Polling loop stopped.")


# --- Main Application ---
class FuzzerNotifierApp:
    def __init__(self):
        self.config_manager = ConfigManager()  # Loads config on init
        self.state_manager = StateManager(self.config_manager)

        notifiers_conf = self.config_manager.get("notifiers", {})
        slack_global_opts = self.config_manager.get("slack_message_options", {})
        self.notifiers: List[NotificationService] = []
        if "email" in notifiers_conf:
            self.notifiers.append(EmailNotifier(notifiers_conf["email"]))
        if "slack" in notifiers_conf:
            self.notifiers.append(
                SlackNotifier(notifiers_conf["slack"], slack_global_opts)
            )

        self.crash_processor = CrashProcessor(
            self.config_manager, self.state_manager, self.notifiers
        )
        self.directory_monitor = DirectoryMonitor(
            self.config_manager, self.crash_processor
        )
        self.running = True

    def _reload_services_on_config_change(self) -> None:
        """Reloads parts of the app that depend heavily on config."""
        logger.info("Configuration changed, reloading dependent services.")
        # ConfigManager already reloaded itself.
        # StateManager filepath might change
        self.state_manager.load_state()  # Reloads state based on potentially new file path in config
        # NOTE: This clears and reloads g_reported_unique_crash_ids
        # which is fine as the file is the source of truth.
        # But if the *file path* itself changes, old state is lost.
        # This is acceptable for now.

        # Re-initialize notifiers as their configs might have changed
        notifiers_conf = self.config_manager.get("notifiers", {})
        slack_global_opts = self.config_manager.get("slack_message_options", {})
        self.notifiers.clear()
        if "email" in notifiers_conf:
            self.notifiers.append(EmailNotifier(notifiers_conf["email"]))
        if "slack" in notifiers_conf:
            self.notifiers.append(
                SlackNotifier(notifiers_conf["slack"], slack_global_opts)
            )

        # Update the processor with new notifiers list (if it stores them by copy)
        # If it stores by reference, this might not be strictly needed, but safer.
        self.crash_processor.notifiers = self.notifiers

        # Restart/reconfigure directory monitoring
        if USE_WATCHDOG:
            self.directory_monitor.manage_watchdog_observers()
        # Polling mode will pick up new fuzzer list naturally from ConfigManager

    def run(self) -> None:
        logger.info(
            f"Notifier App starting. PID: {os.getpid()}. Watchdog: {USE_WATCHDOG}"
        )
        self.directory_monitor.start()  # Starts watchdog observers or the polling loop in a blocking way if not threaded

        try:
            while self.running:
                config_check_interval = self.config_manager.get(
                    "config_check_interval_seconds", 60
                )
                time.sleep(config_check_interval)

                if self.config_manager.needs_reload():
                    if self.config_manager.load_config():  # Attempt reload
                        self._reload_services_on_config_change()
                    else:
                        logger.error(
                            "Failed to reload configuration. Continuing with old settings."
                        )

                # If in polling mode, the directory_monitor.start() call is blocking,
                # so this loop only effectively runs its config check for watchdog mode.
                # Polling mode's config check needs to be inside its own loop or handled differently.
                # For simplicity now, polling mode won't get live config updates for its own interval,
                # but will get new fuzzer lists. Watchdog mode is fully hot-reloadable.
                # To fix for polling: run polling in a separate thread, or integrate its config check here.
                # Current polling loop in DirectoryMonitor already refers to self.config_manager
                # so it *will* get new fuzzer lists, but not new poll_interval for its current cycle.

        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received. Shutting down.")
        finally:
            self.stop()

    def stop(self) -> None:
        logger.info("Application stopping...")
        self.running = False
        self.directory_monitor.stop()
        logger.info("Application stopped.")


if __name__ == "__main__":
    app = FuzzerNotifierApp()
    app.run()
