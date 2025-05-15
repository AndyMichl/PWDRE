#!/usr/bin/env python3

# Author: Andrea Michlíková - xmichl11

import argparse
import os

import src.shared as shared
from src.program_task import run_cmd
from src.hashcat_task import run_hashcat
from src.zxcvbn_task import zxcvbn_for_target
from src.files import delete_stats_folder, delete_log_file
from src.latex import (
    zxcvbn_recovered_tex,
    zxcvbn_score_tex,
    hashcat_tex,
    program_tex,
    program_hashcat_tex_table,
    rules_tex_table,
    wordlist_tex_table,
)
from src.analyze_files import analyze_rules, analyze_wordlist


# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Run rule generation and Hashcat.")
    parser.add_argument("--delete-stats", action="store_true", dest="delete_stats", help="Deletes files in results folder before execution")
    parser.add_argument("--delete-log", action="store_true", dest="delete_log", help="Deletes the log file before execution")
    parser.add_argument("--no-log", action="store_false", dest="log", help="Disables logging")
    parser.add_argument("-l", "--log-file", type=str, dest="log_file", help="Set the log file")
    parser.add_argument("-c", "--config", type=str, required=True, help="Set the configuration file")
    parser.set_defaults(delete_stats=False, delete_log=False, log=True, log_file=shared.DEFAULT_LOG_FILE)
    return parser.parse_args()


def main():
    # Parse input arguments and initialize global config
    args = parse_args()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    shared.initialize_shared(script_dir, args)

    con = shared.CONFIG
    con_stats = con.stats
    program_table = False

    # Optionally delete previous statistics and log file
    if args.delete_stats:
        delete_stats_folder(con.general.stats_folder)
    if args.delete_log:
        delete_log_file(args.log_file)

    # Run programs and generate performance graphs
    if (con_stats.time_passwords
        or con_stats.memory_passwords
        or con_stats.rules_passwords
        or con_stats.cpu_passwords):
        run_cmd()  # Execute the rule generation program
        program_tex()  # Generate LaTeX graphs from results
        program_table = True

    # Run Hashcat and generate graph of recovered passwords
    if con_stats.recovered_guesses:
        run_hashcat()
        hashcat_tex()
        program_table = True if program_table else False
    else:
        program_table = False

    # Evaluate rules with zxcvbn and generate statistics and graphs
    if con_stats.zxcvbn_recovered or con_stats.zxcvbn_score:
        if not con_stats.recovered_guesses:
            shared.CONFIG.input.rules_size = [0]
            run_hashcat()

        zxcvbn_for_target()  # Run zxcvbn on passwords

        # Generate graph for zxcvbn recovery stats
        if con_stats.zxcvbn_recovered: 
            zxcvbn_recovered_tex()  
            
        # Generate graph for zxcvbn score distribution
        if con_stats.zxcvbn_score: 
            zxcvbn_score_tex() 

    if program_table:
        program_hashcat_tex_table()

    # Analyze generated rules and create LaTeX table
    # if con_stats.analyze_rules:
    #     analyze_rules()
    #     rules_tex_table()

    # Analyze wordlist and create LaTeX table
    if con_stats.analyze_wordlist:
        analyze_wordlist()
        wordlist_tex_table()

    print("The entire process has been completed.")


if __name__ == "__main__":
    main()
