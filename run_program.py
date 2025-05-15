#!/usr/bin/env python3

# Author: Andrea Michlíková - xmichl11

import argparse
import os
import resource
import subprocess
import time
import psutil
import sys
import select

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Run rule generation.")
    parser.add_argument("-c", "--command", type=str, required=True, help="Command to execute")
    return parser.parse_args()


def setup_process(command, script_dir):
    """Set up and start the process."""
    pipe_r, pipe_w = os.pipe()
    
    process = subprocess.Popen(
        command,
        shell=True,
        cwd=script_dir,  # Set the working directory
        stdout=pipe_w,  # Redirect stdout to the pipe
        stderr=pipe_w,  # Redirect stderr to the pipe
        bufsize=1,  # Line buffering
        universal_newlines=True,  # Enable proper line handling
    )
    return process, pipe_r, pipe_w


def detect_end_of_output(pipe, process):
    """Detect the end of output for specific case with PACK."""
    rlist, _, _ = select.select([pipe], [], [], 0.1)
    if rlist:
        line = pipe.readline()
        if not line:
            return True
        if "[*] Top 10 words" in line:
            process.terminate()
            return True
    return False


def monitor_process(process, pipe, command):
    """Monitor the process and collect statistics."""
    proc = psutil.Process(process.pid)  # Get the process details
    proc.cpu_percent()  # Ignore the first CPU measurement

    start_time = time.time()
    cpu_usage = []  # List to store CPU usage

    while process.poll() is None:
        try:
            # Special handling for "rulegen.py" to detect output and terminate
            if "rulegen.py" in command:
                if detect_end_of_output(pipe, process):
                    break

            # Collect CPU usage, includes child processes
            cpu_usage.append(proc.cpu_percent(0.1))

            children = proc.children(recursive=True)
            for child in children:
                cpu_usage.append(child.cpu_percent(interval=0.1))

        except psutil.NoSuchProcess:
            break

    elapsed_time = time.time() - start_time
    return elapsed_time, cpu_usage


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    args = parse_arguments()

    process = None
    pipe_r = None
    pipe_w = None

    try:
        # Set up the process and pipes
        process, pipe_r, pipe_w = setup_process(args.command, script_dir)
        os.close(pipe_w)  # Close the write end of the pipe, only read from pipe_r

        with os.fdopen(pipe_r, "r", encoding="utf-8", errors="replace") as pipe:
            # Monitor the process and collect statistics
            elapsed_time, cpu_usages = monitor_process(process, pipe, args.command)

            # Terminate the process if it matches "rulegen.py"
            if "rulegen.py" in args.command:
                process.terminate()
            process.wait()  # Wait for the process to finish

            # Handle non-zero exit codes
            if process.returncode != 0 and not "rulegen.py" in args.command:
                output = pipe.read()
                if not output:
                    print("No output captured from the process.")
                raise subprocess.CalledProcessError(
                    process.returncode, args.command, output=output
                )

            # Get resource usage statistics
            resource_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
            max_memory_usage_mb = resource_usage.ru_maxrss / 1024  # Convert to MB

            # Calculate average CPU usage
            avg_cpu = sum(cpu_usages) / len(cpu_usages) if cpu_usages else 0

            # Print the results
            print(f"{elapsed_time:.2f},{max_memory_usage_mb:.2f},{avg_cpu:.2f}", end="")

    except subprocess.CalledProcessError as e:
        # Handle subprocess errors
        print(
            f"Returned non-zero exit status {e.returncode}.\n" f"Output:\n{e.output}\n",
            file=sys.stderr,
        )
        sys.exit(e.returncode)
    except Exception as e:
        # Handle other exceptions
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Ensure the process is terminated if still running
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()


if __name__ == "__main__":
    main()
