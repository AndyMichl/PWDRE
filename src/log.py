# author: Andrea Michlíková

import json
import os
import hashlib
import csv
from collections import defaultdict

import src.shared as shared

########################################################################### LOG
def load_log():
    """Loads the JSON log from the file specified in 'shared.LOG_FILE'."""
    if os.path.exists(shared.LOG_FILE):
        with open(shared.LOG_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_log(log):
    """Saves the given log to 'shared.LOG_FILE'."""
    with open(shared.LOG_FILE, "w") as f:
        json.dump(log, f, indent=4)


def get_command_hash(cmd):
    """Generates a unique SHA-256 hash for the given command string to identify commands in the log."""
    return hashlib.sha256(cmd.encode()).hexdigest()


def log_command(
    cmd,
    status,
    rule_file=None,
    wl=None,
    wl_size=None,
    attack=None,
    target=None,
    time=None,
    memory=None,
    cpu=None,
    rule_size=None,
    progress_line=None,
    recovered_line=None,
    guesses_log10=None,
    score=None,
    error_message=None,
):
    """Logs the result of a command execution into the JSON log.
    - `cmd`: The command string.
    - `status`: The status of the command (e.g., "done", "error").
    - Additional parameters provide information about the command execution.
    """
    log = load_log()
    cmd_hash = get_command_hash(cmd)

    # Create a dictionary with only non-None values
    log[cmd_hash] = {
        "command": cmd,
        "status": status,
        **{
            key: value
            for key, value in {
                "error": error_message,
                "rule_file": rule_file,
            }.items()
            if value is not None
        },
        "stats": {
            key: (dict(value) if isinstance(value, defaultdict) else value)
            for key, value in {
                "wordlist": wl,
                "wordlist_size": wl_size,
                "attack": attack,
                "target": target,
                "time": time,
                "memory": memory,
                "cpu": cpu,
                "rule_size": rule_size,
                "progress": progress_line,
                "recovered": recovered_line,
                "guesses_log10": guesses_log10,
                "score": score,
            }.items()
            if value is not None
        },
    }

    save_log(log)


def has_command_run(cmd):
    """Checks if the given command has already been successfully executed."""
    log = load_log()
    cmd_hash = get_command_hash(cmd)
    return log.get(cmd_hash, {}).get("status") == "done"


def load_stats_from_log(cmd):
    """Loads statistics and rule file information for a given command from the log."""
    log = load_log()
    cmd_hash = get_command_hash(cmd)
    info = log.get(cmd_hash)
    if not cmd_hash or not has_command_run(cmd):
        return {}, None
    return info.get("stats", {}), info.get("rule_file")


########################################################################### Save to CSV
def data_to_csv(csv_path, content, header=None):
    """Logs content to a CSV file. If the file is empty, it automatically adds a header."""
    # Check if the file is empty
    is_empty = not os.path.exists(csv_path) or os.stat(csv_path).st_size == 0

    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # If the file is empty and a header is defined, write it
        if is_empty and header:
            writer.writerow(header)
        # Write the content
        writer.writerow(content)


def program_to_csv(program, run_index, rule_file, wordlist, size, time, memory, cpu, rule_size):
    """
    Log program execution data to a CSV file.
    - `program`: Name of the program.
    - `run_index`: Index of the run.
    - `rule_file`: Path to the rule file.
    - `wordlist`: Path to the wordlist.
    - `size`: Size of the wordlist.
    - `time`: Execution time.
    - `memory`: Memory usage.
    - `cpu`: CPU usage.
    - `rule_size`: Size of the rule file.
    """
    csv_path = shared.CONFIG.stats.program_csv_file

    header = ["program", "run_index", "rule_file", "wordlist", "size", "time", "memory", "cpu", "rules"]
    data = [program, run_index, rule_file, wordlist, size, time, memory, cpu, rule_size]
    data_to_csv(csv_path, data, header)


def hashcat_to_csv(rule_file, size, attack, attack_size, target, progress, recovered):
    """
    Logs Hashcat execution data to a CSV file.
    - `rule_file`: Path to the rule file.
    - `size`: Size of the rule file.
    - `attack`: Path to the attack file.
    - `attack_size`: Size of the attac file.
    - `target`: Path to the target file.
    - `progress`: Number of progress passwords.
    - `recovered`: Percent of recovered passwords.
    """
    csv_path = shared.CONFIG.stats.hashcat_csv_file

    header = ["rule_file", "rule_size", "attack", "attack_size", "target", "progress", "recovered"]
    data = [rule_file, size, attack, attack_size, target, progress, recovered]
    data_to_csv(csv_path, data, header)


def zxcvbn_recovered_to_csv(file_name, recovered, guesses_log10):
    """
    Logs zxcvbn recovery data to a CSV file.
    - `file_name`: Name of the file being analyzed.
    - `recovered`: Percent of recovered passwords.
    - `guesses_log10`: Logarithmic guesses data.
    """
    csv_path = shared.CONFIG.stats.zxcvbn_recovered_csv_file

    header = ["file_name", "recovered", "guesses_log10", "n"]
    for guesses_log10, count in sorted(guesses_log10.items()):
        data = [file_name, recovered, guesses_log10, count]
        data_to_csv(csv_path, data, header)


def zxcvbn_score_to_csv(file_name, recovered, score):
    """
    Logs zxcvbn score data to a CSV file.
    - `file_name`: Name of the file being analyzed.
    - `recovered`: Percent of recovered passwords.
    - `score`: Score distribution.
    """
    csv_path = shared.CONFIG.stats.zxcvbn_score_csv_file

    header = ["file_name", "recovered"] + [f"score_{i}" for i in range(5)]
    data = [file_name, recovered] + [score[i] for i in range(5)]
    data_to_csv(csv_path, data, header)


def rules_to_csv(file_name, rule_order, rule_counts):
    """
    Logs the analysis of rules to a CSV file.
    - `file_name`: Name of the file being analyzed.
    - `rule_order`: List of rules in the desired order.
    - `rule_counts`: Dictionary containing counts for each rule.
    """
    csv_path = shared.CONFIG.stats.rules_csv_file

    header = ["rule_file"] + list(rule_order)
    data = [file_name] + [rule_counts.get(rule, 0) for rule in rule_order]
    data_to_csv(csv_path, data, header)


def wordlist_to_csv(wl_path, wl_size, avg_len, median_len, avg_entropy, entropy_above, ascii, charset_counts):
    """
    Logs wordlist statistics to a CSV file.
    - `wordlist_path`: Path to the wordlist file.
    - `wl_size`: Total size of words in the wordlist.
    - `avg_len`: Average length of words in the wordlist.
    - `median_len`: Median length of words in the wordlist.
    - `avg_entropy`: Average entropy of the words.
    - `entropy_above`: Number of words with entropy above a threshold.
    - `ascii`: Number of words that contains only ASCII characters.
    - `charset_counts`: Dictionary with counts of characters by charset.
    """
    csv_path = shared.CONFIG.stats.wordlist_csv_file

    header = ["wordlist", "size", "avg_len", "median_len", "avg_entropy", "entropy_above", "ascii"] + list(charset_counts.keys())

    data = [wl_path, wl_size, avg_len, median_len, avg_entropy, entropy_above, ascii] + list(charset_counts.values())

    data_to_csv(csv_path, data, header)


########################################################################### Is record in CSV
def is_program_record_in_csv(rule_file, wordlist):
    """
    Checks if a specific program record already exists in the program CSV file.
    - `rule_file`: Path to the rule file.
    - `wordlist`: Path to the wordlist file.
    Returns True if the record exists, otherwise False.
    """
    csv_path = shared.CONFIG.stats.program_csv_file

    if not os.path.exists(csv_path):
        return False

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("rule_file") == rule_file and row.get("wordlist") == wordlist:
                return True
    return False


def is_hashcat_record_in_csv(rule_file, size, attack, target):
    """
    Checks if a specific hashcat record already exists in the hashcat CSV file.
    - `rule_file`: Path to the rule file.
    - `size`: Size of the rule file.
    - `attack`: Path to the attack file.
    - `target`: Path to the target file.
    Returns True if the record exists, otherwise False.
    """
    csv_path = shared.CONFIG.stats.hashcat_csv_file

    if not os.path.exists(csv_path):
        return False

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if (
                row.get("rule_file") == rule_file
                and row.get("rule_size") == str(size)
                and row.get("attack") == attack
                and row.get("target") == target
            ):
                return True
    return False


def is_file_record_in_csv(csv_path, key, file):
    """
    Checks if a specific file record exists in a given CSV file.
    - `csv_path`: Path to the CSV file.
    - `key`: Column name to check.
    - `file`: Value to search for in the specified column.
    Returns True if the record exists, otherwise False.
    """
    if not os.path.exists(csv_path):
        return False
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get(key) == file:
                return True
    return False


########################################################################### Load from LOG to CSV
def program_from_log_to_csv(cmd, program, i):
    """
    Logs program statistics from the log to the program CSV file.
    - `cmd`: Command string used to retrieve the log entry.
    - `program`: Name of the program.
    - `i`: Index of the run.
    """
    stats, rule_file = load_stats_from_log(cmd)

    if stats:
        program_to_csv(
            program,
            i,
            rule_file,
            stats["wordlist"],
            stats["wordlist_size"],
            stats["time"],
            stats["memory"],
            stats["cpu"],
            stats["rule_size"],
        )
        print(f"Program statistics were retrieved from LOG.")
    else:
        print(f"No program statistics found for '{cmd}'.")


def hashcat_from_log_to_csv(cmd, rule_size, attack_size):
    """
    Logs hashcat statistics from the log to the hashcat CSV file.
    - `cmd`: Command string used to retrieve the log entry.
    - `rule_size`: Size of the rule file.
    - `attack_size`: Size of the attack file.
    """
    stats, rule_file = load_stats_from_log(cmd)

    if stats:
        hashcat_to_csv(
            rule_file,
            rule_size,
            stats["attack"],
            attack_size,
            stats["target"],
            stats["progress"],
            stats["recovered"],
        )
        print(f"Hashcat statistics were retrieved from LOG.")
    else:
        print(f"No Hashcat statistics found for '{cmd}'.")


def zxcvbn_from_log_to_csv(cmd, file_name):
    """
    Logs zxcvbn statistics from the log to the zxcvbn CSV files.
    - `cmd`: Command string used to retrieve the log entry.
    """
    stats, _ = load_stats_from_log(cmd)

    if stats:
        # Log recovery data to the zxcvbn_recovered CSV
        if shared.CONFIG.stats.zxcvbn_recovered:
            zxcvbn_recovered_to_csv(
                file_name,
                stats.get("recovered", "0.00"),
                stats.get("guesses_log10", {}),
            )

        # Log score data to the zxcvbn_score CSV
        if shared.CONFIG.stats.zxcvbn_score:
            score = stats.get("score", {})
            score = {int(k): v for k, v in score.items()}
            zxcvbn_score_to_csv(
                file_name,
                stats.get("recovered", "0.00"),  # Default to "0.00" if missing
                score,
            )

        print(f"zxcvbn statistics were retrieved from LOG.")
    else:
        print(f"No zxcvbn statistics found for '{cmd}'.")
