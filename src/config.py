# Author: Andrea Michlíková - xmichl11

import yaml
from dataclasses import dataclass, field
from typing import List


@dataclass
class Program:
    name: str  # Name of the program
    run: str  # Executable command for the program
    args: List[str] = field(
        default_factory=list
    )  # List of arguments for the program runs


# General configuration for the application
@dataclass
class GeneralConfig:
    wordlist: str = ""  # Path to the wordlist file
    attack: str = ""  # Path to the attack file or folder
    target: str = ""  # Path to the target file or folder
    rules_file: str = ""  # Model name of the rules file
    hashcat_folder: str = ""  # Path to the folder for attack with Hashcat
    stats_folder: str = "results"  # Folder to store statistics


# Configuration for statistics collection
@dataclass
class StatsConfig:
    # Enable/disable statistics
    time_passwords: bool = False
    memory_passwords: bool = False
    cpu_passwords: bool = False
    rules_passwords: bool = False
    recovered_guesses: bool = False
    zxcvbn_recovered: bool = False
    zxcvbn_score: bool = False
    analyze_rules: bool = False
    analyze_wordlist: bool = False

    # File paths for storing statistics
    time_passwords_file: str = "time_passwords.tex"
    memory_passwords_file: str = "memory_passwords.tex"
    cpu_passwords_file: str = "cpu_passwords.tex"
    rules_passwords_file: str = "rules_passwords.tex"
    recovered_guesses_file: str = "recovered_guesses.tex"
    zxcvbn_recovered_file: str = "zxcvbn_recovered.tex"
    zxcvbn_score_file: str = "zxcvbn_score.tex"
    analyze_rules_file: str = "analyze_rules.tex"
    analyze_wordlist_file: str = "analyze_wordlist.tex"

    # CSV file paths for storing statistics
    program_csv_file: str = "program_stats.csv"
    hashcat_csv_file: str = "hashcat_stats.csv"
    zxcvbn_recovered_csv_file: str = "zxcvbn_recovered_stats.csv"
    zxcvbn_score_csv_file: str = "zxcvbn_score_stats.csv"
    rules_csv_file: str = "analyze_rules.csv"
    wordlist_csv_file: str = "analyze_wordlist.csv"


# Configuration for input data
@dataclass
class InputConfig:
    wordlist_size: List[int] = field(default_factory=list)  # List of wordlist sizes
    rules_size: List[int] = field(default_factory=list)  # List of rules sizes


# Main configuration class that combines all configurations
@dataclass
class Config:
    programs: List[Program]  # List of program configurations
    general: GeneralConfig  # General configuration
    stats: StatsConfig  # Statistics configuration
    input: InputConfig  # Input configuration

    # Static method to load configuration from a YAML file
    @staticmethod
    def load(file_path: str) -> "Config":
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)

        # Extract individual sections from the YAML data
        general_data = data.get("general", {})
        input_data = data.get("input", {})
        stats_data = data.get("stats", {})

        # Create a Config object with the loaded data
        config = Config(
            general=GeneralConfig(**general_data),
            programs=[
                Program(
                    name=prog["program"],  # Program name
                    run=prog.get("run", ""),  # Executable command
                    args=prog.get("args", []),  # Arguments
                )
                for prog in data.get("programs", [])  # Iterate over programs
            ],
            stats=StatsConfig(**stats_data),
            input=InputConfig(**input_data),
        )

        # Validate configuration: rules_file must be set if certain stats are enabled
        if (
            config.stats.time_passwords
            or config.stats.memory_passwords
            or config.stats.cpu_passwords
            or config.stats.rules_passwords
        ) and not config.general.rules_file:
            raise ValueError(
                "ERROR: rules_file must be set in general section if programs stats are enabled"
            )

        return config
