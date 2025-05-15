# Author: Andrea Michlíková - xmichl11

import os
from collections import defaultdict
from zxcvbn import zxcvbn

from src.log import log_command, zxcvbn_recovered_to_csv, zxcvbn_score_to_csv, is_file_record_in_csv
import src.shared as shared


def analyze_passwords(file_path: str):
    """Analyzes passwords in the given file and calculates statistics."""
    guesses_log10 = defaultdict(int)
    score = defaultdict(int)

    # Initialize score dictionary with keys 0-4
    for i in range(5):
        score[i]

    with open(file_path, "r") as file:
        for line in file:
            password = line.strip()
            # Skip empty lines and passwords longer than 72 characters
            if password and len(password) <= 72:
                results = zxcvbn(password)
                # Round guesses_log10 to the nearest 0.5 and count occurrences
                tmp = round(results['guesses_log10'] * 2) / 2
                guesses_log10[tmp] += 1
                tmp = results['score']
                score[tmp] += 1

    return guesses_log10, score


def run_zxcvbn(cmd, file, recovered=100.0, rule=False):
    """Processes zxcvbn output and saves statistics."""
    guesses_log10 = {}
    score = {}

    # Analyze the recovered file or analyze the given file
    if rule:
        guesses_log10, score = analyze_passwords(shared.RECOVERED_FILE)
    else:
        guesses_log10, score = analyze_passwords(file)

    # Save recovered statistics to CSV if not already logged
    if (shared.CONFIG.stats.zxcvbn_recovered and
        not is_file_record_in_csv(shared.CONFIG.stats.zxcvbn_recovered_csv_file, "file_name", file)):
        zxcvbn_recovered_to_csv(file, recovered, guesses_log10)

    # Save score statistics to CSV if not already logged
    if (shared.CONFIG.stats.zxcvbn_score and
        not is_file_record_in_csv(shared.CONFIG.stats.zxcvbn_score_csv_file, "file_name", file)):
        zxcvbn_score_to_csv(file, recovered, score)

    log_command(cmd, "done", recovered_line=recovered, guesses_log10=guesses_log10, score=score)

    if os.path.exists(shared.RECOVERED_FILE):
        os.remove(shared.RECOVERED_FILE)


def zxcvbn_for_target():
    """Runs zxcvbn analysis for all target files in the shared.TARGET_LIST."""
    for t in shared.TARGET_LIST:
     
        if (not is_file_record_in_csv(shared.CONFIG.stats.zxcvbn_recovered_csv_file, "file_name", t)
            or not is_file_record_in_csv(shared.CONFIG.stats.zxcvbn_score_csv_file, "file_name", t)):
            run_zxcvbn(f"zcvbn T:{t}", t)
