import os
import time
import random
import string
import argparse
from datetime import datetime


def generate_random_string(length=8):
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(length)
    )


def main():
    parser = argparse.ArgumentParser(
        description="Simulate a fuzzer creating crash files."
    )
    parser.add_argument("fuzzer_name", help="Name of the fuzzer (for filename prefix)")
    parser.add_argument("crash_dir", help="Directory to create crash files in")
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Interval in seconds between creating crashes",
    )
    parser.add_argument(
        "--num_crashes",
        type=int,
        default=3,
        help="Number of crashes to simulate (0 for infinite)",
    )
    parser.add_argument(
        "--crash_on_input",
        type=str,
        default="CRASH",
        help="Content that causes a crash",
    )
    parser.add_argument("--empty", action="store_true", help="Create empty crash files")

    args = parser.parse_args()

    if not os.path.isdir(args.crash_dir):
        print(
            f"Warning: Crash directory '{args.crash_dir}' does not exist. Attempting to create it."
        )
        try:
            os.makedirs(args.crash_dir, exist_ok=True)
            print(f"Successfully created directory: {args.crash_dir}")
        except OSError as e:
            print(f"Error: Could not create crash directory '{args.crash_dir}': {e}")
            return

    print(f"Simulating fuzzer '{args.fuzzer_name}' outputting to '{args.crash_dir}'")
    print(
        f"Creating a crash every {args.interval} seconds. Content: '{args.crash_on_input}'"
    )
    if args.num_crashes > 0:
        print(f"Will create {args.num_crashes} crash(es).")
    else:
        print("Will create crashes indefinitely (Ctrl+C to stop).")

    crashes_created = 0
    try:
        while True:
            if args.num_crashes > 0 and crashes_created >= args.num_crashes:
                print("Reached maximum number of simulated crashes.")
                break

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            random_suffix = generate_random_string(6)

            # Mimic different fuzzer naming conventions
            filename_base = f"time_{timestamp}_{random_suffix}"
            if "libfuzzer" in args.fuzzer_name.lower():
                filename = f"crash-{random_suffix}"
            elif "afl" in args.fuzzer_name.lower():
                q_id = str(crashes_created).zfill(6)
                # Simplified AFL-like name for testing
                filename = f"id_{q_id}_{filename_base}.crash"
            else:
                filename = f"{args.fuzzer_name}_crash_{filename_base}.txt"

            file_path = os.path.join(args.crash_dir, filename)

            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] Creating crash file: {file_path}"
            )
            try:
                with open(file_path, "w") as f:
                    if not args.empty:
                        f.write(
                            args.crash_on_input
                            + "\n"
                            + f"Simulated by {args.fuzzer_name} at {timestamp}\n"
                        )
                    else:
                        f.write("")  # Empty file
                # Small delay to ensure file system registers creation before notifier might check (if polling very fast)
                time.sleep(0.1)
            except IOError as e:
                print(f"Error writing file {file_path}: {e}")
                # Potentially skip this crash and continue, or retry
                time.sleep(args.interval)  # Wait before next attempt
                continue

            crashes_created += 1

            if args.num_crashes == 0 or crashes_created < args.num_crashes:
                time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nSimulation stopped by user.")
    finally:
        print("Simulation finished.")


if __name__ == "__main__":
    main()
