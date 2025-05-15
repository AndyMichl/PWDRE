# Author: Andrea Michlíková - xmichl11

import os
import re
import subprocess
import src.shared as shared
from src.log import (
    has_command_run,
    log_command,
    hashcat_to_csv,
    is_file_record_in_csv,
    is_hashcat_record_in_csv,
    hashcat_from_log_to_csv,
    zxcvbn_from_log_to_csv,
)
from src.files import count_lines_in_file, get_rules_list, create_temporary_file
from src.zxcvbn_task import run_zxcvbn


def extract_lines(output):
    """Extracts progress and recovered information from Hashcat output."""
    progress_line = None
    recovered_percentage = None
    hashcat_lines = output.splitlines()

    for line in hashcat_lines:
        if line.startswith("Progress"):
            match = re.search(r"Progress\.+:\s(\d+)", line)
            if match:
                progress_line = match.group(1)

        if line.startswith("Recovered"):
            match = re.search(r"\((\d+\.\d+)%\)", line)
            if match:
                recovered_percentage = match.group(1)

    return progress_line, recovered_percentage


def prepare_rulefile(rule_file, size):
    """Prepares a temporary rule file if a size limit is specified."""
    if size != 0:
        temp_rf = create_temporary_file(rule_file, size)
        is_temp = True
    else:
        temp_rf = rule_file
        is_temp = False
    return temp_rf, is_temp


def get_cmd(in_size, target_file, attack_file, temp_rf):
    """Generates the Hashcat command based on input size and file paths."""
    if in_size == 0:
        return f"hashcat -a 0 -m 99999 {target_file} {attack_file} -r {temp_rf} -o {shared.RECOVERED_FILE} --outfile-format=1 --potfile-disable"
    else:
        return f"hashcat -a 0 -m 99999 {target_file} {attack_file} -r {temp_rf} --potfile-disable"


def process_run(rule_file, target_file, attack_file, attack_size, in_size):
    """Processes a single run of Hashcat with the given parameters."""
    con_stats = shared.CONFIG.stats
    zxcvbn_recovered = shared.CONFIG.stats.zxcvbn_recovered
    zxcvbn_score = shared.CONFIG.stats.zxcvbn_score

    in_size = int(in_size)
    temp_rf, is_temp = prepare_rulefile(rule_file, in_size)
    if not temp_rf: return
    
    temp_size = in_size
    if in_size == 0:
        temp_size = count_lines_in_file(temp_rf)

    # Build command for Hashcat and zxcvbn
    cmd = get_cmd(in_size, target_file, attack_file, temp_rf)
    zxcvbn_cmd = f"zcvbn R:{rule_file} A:{attack_file} T:{target_file}"

    # Check if the command has already been run
    if shared.LOG and has_command_run(cmd):
        print(f"ALREADY RUN {cmd}")
        if (shared.CONFIG.stats.recovered_guesses and not is_hashcat_record_in_csv(rule_file, temp_size, attack_file, target_file)):
            hashcat_from_log_to_csv(cmd, temp_size, attack_size)
            
        # Load zxcvbn record from log to CSV
        print(f"{zxcvbn_cmd}")
        if (zxcvbn_recovered or zxcvbn_score):
            if (not is_file_record_in_csv(con_stats.zxcvbn_recovered_csv_file, "file_name", rule_file)
                and not is_file_record_in_csv(con_stats.zxcvbn_score_csv_file, "file_name", rule_file)):
                zxcvbn_from_log_to_csv(zxcvbn_cmd, rule_file)
        return

    print(f"RUN: {cmd}")
    process = subprocess.run(cmd, capture_output=True, shell=True, cwd=shared.SCRIPT_DIR)
    stdout = process.stdout.decode(errors="replace")
    progress_line, recovered_line = extract_lines(stdout)

    if shared.LOG:
        log_command(
            cmd,
            "done",
            rule_file=rule_file,
            rule_size=str(temp_size),
            attack=attack_file,
            target=target_file,
            progress_line=progress_line,
            recovered_line=recovered_line,
        )
    hashcat_to_csv(rule_file, temp_size, attack_file, attack_size, target_file, progress_line, recovered_line)

    # Run zxcvbn analysis
    if in_size == 0 and (zxcvbn_recovered or zxcvbn_score):
        if (not is_file_record_in_csv(con_stats.zxcvbn_recovered_csv_file, "file_name", rule_file)
            and not is_file_record_in_csv( con_stats.zxcvbn_score_csv_file, "file_name", rule_file)):
            run_zxcvbn(zxcvbn_cmd, rule_file, recovered_line, True)

    # Delete temporary file
    if is_temp:
        print(f"{temp_rf} was deleted")
        os.remove(temp_rf)
    if os.path.exists(shared.RECOVERED_FILE):
        print(f"{shared.RECOVERED_FILE} was deleted")
        os.remove(shared.RECOVERED_FILE)


def run_hashcat():
    """Main function to run Hashcat."""
    rules_files = get_rules_list()

    for attack_file in shared.ATTACK_LIST:
        attack_size = count_lines_in_file(attack_file)
        for target_file in shared.TARGET_LIST:
            for rule_file in rules_files:
                if not os.path.exists(rule_file):
                    print("Hashcat: Rule file not found.")
                    exit(-1)
                    break
                for k, in_size in enumerate(shared.CONFIG.input.rules_size):
                    process_run(rule_file, target_file, attack_file, attack_size, in_size)
