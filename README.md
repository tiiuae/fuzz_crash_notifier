# Fuzzer Crash Notifier

A Python-based notification system designed to monitor fuzzer crash directories and send alerts via Email and/or Slack when new crashes are discovered. This tool helps automate the monitoring of long-running fuzzing campaigns.

## Demo

![Demo](img/demo.png)

## Features

- **Real-time Monitoring:** Utilizes `watchdog` for efficient, event-based file system monitoring. Falls back to periodic polling if `watchdog` is not available.
- **Multi-Fuzzer Support:** Monitor crash directories from multiple fuzzing campaigns simultaneously (e.g., libAFL, AFL++, libFuzzer).
- **Configurable Notifiers:**
  - **Email:** Send notifications via SMTP.
  - **Slack:** Send notifications to a Slack channel using Incoming Webhooks.
- **Rich Slack Messages:** Uses Slack Block Kit for well-formatted messages including:
  - Fuzzer Name
  - Timestamp of Crash
  - Reproducer Filename and Path
  - Reproducer File Size
  - Hostname of the reporting machine
  - Configurable Content Snippet (text or hexdump format) of the reproducer.
- **Stateful Reporting:** Remembers reported crashes (in `reported_crashes.txt`) to prevent duplicate notifications for the same crash file.
- **Hot-Reloading Configuration:** The `config.json` file can be modified while the notifier is running. Changes (like adding new fuzzer directories to watch) are picked up automatically without restarting the service or re-notifying old crashes.
- **File Logging:** Logs activity and errors to `notifier.log` in addition to console output.

## Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) for managing the dependency installation.

## Installation

1.  **Clone the repository (or download the files):**
    If you have it in a git repo:

    ```bash
    git clone https://github.com/tiiuae/fuzz_crash_notifier.git
    cd fuzz_notifier
    ```

    Otherwise, just ensure `notify.py` and an initial `config.json` are in the same directory.

## Configuration (`config.json`)

The notifier is configured using a `config.json` file in the same directory as the script. Below is an explanation of the available options. You should create this file based on the example structure.

### Main Configuration Options:

- **`notifiers`**: This object contains settings for different notification channels.
  - **`email`**: Holds email notification settings.
    - `enabled`: Set to `true` to enable email notifications, `false` to disable.
    - `smtp_server`: The hostname or IP address of your SMTP server (e.g., `"smtp.gmail.com"`).
    - `smtp_port`: The port number for the SMTP server (e.g., `587` for TLS, `465` for SSL).
    - `smtp_user`: Your email address for SMTP authentication.
    - `smtp_password`: Your email password or an app-specific password (recommended for services like Gmail).
    - `recipient_email`: The email address where crash notifications will be sent.
  - **`slack`**: Holds Slack notification settings.
    - `enabled`: Set to `true` to enable Slack notifications, `false` to disable.
    - `webhook_url`: Your Slack Incoming Webhook URL. This is obtained from your Slack app's configuration.
- **`fuzzers_to_watch`**: This is an array of objects, where each object defines a fuzzer campaign to monitor.
  - `name`: A user-friendly name for this fuzzer campaign (e.g., `"LibAFL_TargetA"`). This name is used in notifications.
  - `crash_dir`: The full or relative path to the directory where this specific fuzzer instance saves its crash files (e.g., `"/path/to/your/libafl_campaign/output_dir/crashes"`).
    - For _LibAFL/AFL++_: This is typically `output_dir/[instance_name_if_distributed]/crashes/`.
    - For _LibFuzzer_: This is the directory specified by the `-artifact_prefix=path/to/dir/` argument when running libFuzzer, or the current working directory if `artifact_prefix` is not used.
- **`reported_crashes_file`** (String, Default: `"reported_crashes.txt"`): The path to a file where the script will store the identifiers of crashes that have already been reported. This prevents sending duplicate notifications for the same crash file if the notifier is restarted. The format of each line in this file is `FuzzerName::FileName`.
- `reported_unique_crashes_file` (String, Default: `"reported_unique_crashes.txt"`): Path to the file used to store identifiers (fuzzer_name::sha256_hash) of already reported unique crash contents to enable deduplication.
- `min_crash_file_size_bytes` (Integer, Default: `1`): The minimum size (in bytes) a file must be to be considered a potential crash; files smaller than this will be ignored.
- **`check_interval_seconds`** (Integer, Default: `10`): If the `watchdog` library is not available and the script falls back to polling mode, this value determines how often (in seconds) the configured `crash_dir` directories are scanned for new files.
- **`config_check_interval_seconds`** (Integer, Default: `60`): How often (in seconds) the `config.json` file itself is checked for any modifications. If changes are detected, the configuration is hot-reloaded.
- **`watchdog_file_settle_delay_ms`** (Integer, Default: `500`): When using `watchdog` mode, this is a small delay (in milliseconds) introduced after a file creation event is detected before the script processes the file. This helps ensure that the fuzzer has completely finished writing the crash file, especially for larger files or slower I/O operations.
- **`slack_message_options`**: This object contains settings specifically for customizing the content and format of Slack messages.
  - `show_content_snippet` (Boolean, Default: `true`): If `true`, a snippet of the crash file's content will be included in the Slack notification.
  - `content_snippet_format` (String, Default: `"hexdump"`): Specifies the format for the content snippet. Valid options are:
    - `"hexdump"`: Displays the snippet as a hexadecimal dump (similar to `hexdump -C`).
    - `"text"`: Displays the snippet as plain text (first few lines).
  - `content_snippet_hexdump_bytes` (Integer, Default: `64`): If `content_snippet_format` is `"hexdump"`, this is the total number of bytes from the beginning of the file that will be included in the hexdump.
  - `content_snippet_hexdump_bytes_per_line` (Integer, Default: `16`): If `content_snippet_format` is `"hexdump"`, this is the number of bytes displayed per line in the hexdump output.
  - `content_snippet_max_lines` (Integer, Default: `5`): If `content_snippet_format` is `"text"`, this is the maximum number of lines from the beginning of the file to include in the snippet.
  - `content_snippet_max_bytes_per_line` (Integer, Default: `100`): If `content_snippet_format` is `"text"`, this is the maximum number of bytes to display for any single line before it's truncated (to prevent overly long lines in the notification).
  - `content_snippet_text_max_total_bytes` (Integer, Default: `1024`): If `content_snippet_format` is `"text"`, this is the overall maximum number of bytes to read from the file for generating the text snippet, to prevent trying to process extremely large files as text.
  - `include_hostname` (Boolean, Default: `true`): If `true`, the hostname of the machine where the notifier script is running will be included in the Slack notification. This is useful if you're running multiple notifiers on different hosts.

## Usage

1.  **Prepare `config.json`:** Create a `config.json` file in the same directory as `notify.py`. Populate it with your fuzzer paths and notification settings according to the options described above.
2.  **Run the script:**
    ```bash
    python notify.py
    ```
3.  **Keep it running:** For long-term monitoring, run it in the background using tools like `screen`, `tmux`, or `nohup`:
    ```bash
    nohup python notify.py > notifier_daemon.log 2>&1 &
    ```
    Alternatively, consider setting it up as a systemd service for more robust background operation.

## How It Works

- The script starts by loading its configuration (`config.json`) and the list of previously reported unique crash hashes (from the file specified by `reported_unique_crashes_file`, e.g., `reported_unique_crashes.txt`).
- If the `watchdog` library is available, it sets up observers to monitor the specified `crash_dir` for each configured fuzzer. When a new file is created in a monitored directory, `watchdog` triggers an event.
- If `watchdog` is not available, the script falls back to periodically polling the configured crash directories at the interval defined by `check_interval_seconds`.
- When a new file is detected in a crash directory:
  1.  The script first checks if the file meets a minimum size requirement (configurable via `min_crash_file_size_bytes`) to filter out empty or tiny, potentially irrelevant files.
  2.  The MD5 and SHA256 hashes of the file's content are calculated.
  3.  A unique crash identifier is formed using `FuzzerName::SHA256Hash`.
  4.  This identifier is checked against the in-memory set of `g_reported_unique_crash_ids` (loaded from the unique crashes file).
  5.  **If the `FuzzerName::SHA256Hash` is new for that fuzzer:**
      - It's considered a new unique crash.
      - The script gathers the fuzzer name, timestamp (file creation/modification), filename, file path, file size, the calculated MD5 and SHA256 hashes, and (if configured) a content snippet (text or hexdump).
      - Notifications are sent via any enabled email and/or Slack channels with this information.
      - The `FuzzerName::SHA256Hash` identifier is added to `g_reported_unique_crash_ids` (in memory) and appended to the unique crashes file (e.g., `reported_unique_crashes.txt`).
  6.  **If the `FuzzerName::SHA256Hash` has already been reported for that fuzzer:**
      - The script logs that a duplicate crash (by content) was found under a potentially new filename and skips sending a notification. This significantly reduces alert fatigue for recurring crash conditions.
- The script periodically checks `config.json` for modifications (at the interval defined by `config_check_interval_seconds`).
- If the configuration file is updated, the script reloads the settings. This includes updating fuzzer configurations, notification settings, etc.
  - If using `watchdog`, existing observers are stopped, and new ones are started based on the updated fuzzer list and their `crash_dir` paths.
  - The in-memory set of `g_reported_unique_crash_ids` (containing `FuzzerName::SHA256Hash` entries) is **preserved** across configuration reloads to ensure that previously reported unique crashes are not re-notified.

## TODOs

- [ ] Enhanced messages with:
  - [ ] Stack trace snippet
  - [ ] Crash Type/Signal
  - [ ] Reproducability status
- [ ] Throttling/Debouncing notifications for very noisy fuzzers.
- [ ] Option to attach reproducer files directly to emails or upload to Slack.
- [ ] Basic crash triaging (root-cause analysis) integration.
- [ ] Support for more notification platforms (Discord, MS Teams).
- [ ] Interactive Slack buttons (e.g., Acknowledge, Triage).

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.
