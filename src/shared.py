# Author: Andrea Michlíková - xmichl11

import os
from src.config import Config
from src.files import get_files, make_filepath

# Default log file path
DEFAULT_LOG_FILE = "log/log.json"

# Default recovered file path
RECOVERED_FILE = "recovered.potfile"

CONFIG = None
SCRIPT_DIR = None  # Directory of the script
LOG = None  # Enabled/Disabled logging
LOG_FILE = None  # Full path to the log file

WORDLIST_LIST = []  # List of wordlist files
TARGET_LIST = []  # List of target files
ATTACK_LIST = []  # List of attack files


def initialize_filepaths(config):
    """Updates file paths in config."""
    for attr_name in dir(config.stats):
        if attr_name.endswith("_file"):
            file_name = getattr(config.stats, attr_name)
            file_path = make_filepath(config.general.stats_folder, file_name)
            setattr(config.stats, attr_name, file_path)


def initialize_shared(script_directory, args):
    """Initialize global variables."""
    global SCRIPT_DIR
    SCRIPT_DIR = script_directory

    global CONFIG
    CONFIG = Config.load(os.path.join(SCRIPT_DIR, args.config))
    initialize_filepaths(CONFIG)

    global LOG
    LOG = args.log
    global LOG_FILE
    LOG_FILE = os.path.join(SCRIPT_DIR, args.log_file)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    global WORDLIST_LIST
    WORDLIST_LIST = get_files(CONFIG.general.wordlist)

    global TARGET_LIST
    TARGET_LIST = get_files(CONFIG.general.target)

    global ATTACK_LIST
    ATTACK_LIST = get_files(CONFIG.general.attack)


# Rule definitions with their descriptions in English and Czech
RULE_ORDER = {
    ":": ("Nothing", "Bez změny"),
    "l": ("Lowercase", "Malá písmena"),
    "u": ("Uppercase", "Velká písmena"),
    "c": ("Capitalize", "První velké"),
    "C": ("Invert Capitalize", "První malé"),
    "t": ("Toggle Case", "Změnit velikost"),
    "T": ("Toggle @", "Změnit velikost @ N"),
    "r": ("Reverse", "Obrátit"),
    "d": ("Duplicate", "Duplikovat"),
    "p": ("Duplicate N", "Duplikovat N"),
    "f": ("Reflect", "Zrcadlit"),
    "{": ("Rotate Left", "Posun doleva"),
    "}": ("Rotate Right", "Posun doprava"),
    "$": ("Append Character", "Přidat na konec"),
    "^": ("Prepend Character", "Přidat na začátek"),
    "[": ("Truncate Left", "Oříznout zleva"),
    "]": ("Truncate Right", "Oříznout zprava"),
    "D": ("Delete @ N", "Smazat @ N"),
    "x": ("Extract range", "Vyjmout rozsah"),
    "O": ("Omit range", "Vynechat rozsah"),
    "i": ("Insert @ N", "Vložit @ N"),
    "o": ("Overwrite @ N", "Přepsat @ N"),
    "'": ("Truncate @ N", "Oříznout @ N"),
    "s": ("Replace", "Nahradit X za Y"),
    "@": ("Purge", "Odstranit všechny X"),
    "z": ("Duplicate first N", "Duplikovat první N"),
    "Z": ("Duplicate last N", "Duplikovat poslední N"),
    "q": ("Duplicate all", "Duplikovat vše"),
    "other": ("Other", "Ostatní"),
}

# Grouping of rules with their descriptions in Czech
RULE_GROUPS = {
    "Lowercase": {
        "rules": ["l"],
        "cz_name": "Malá písmena",
    },
    "Uppercase": {
        "rules": ["u"],
        "cz_name": "Velká písmena",
    },
    "Change Capitalize": {
        "rules": ["c", "C", "t", "T"],
        "cz_name": "Změnění velikosti",
    },
    "Duplicate": {
        "rules": ["d", "p", "z", "Z", "q", "f"],
        "cz_name": "Duplikování",
    },
    "Rotate": {
        "rules": ["r", "{", "}"],
        "cz_name": "Posunutí",
    },
    "Delete characters": {
        "rules": ["D", "@", "[", "]", "'", "x", "O"],
        "cz_name": "Odstranění",
    },
    "Insert characters": {
        "rules": ["$", "^", "i"],
        "cz_name": "Přidání",
    },
    "Overwrite characters": {
        "rules": ["o", "s"],
        "cz_name": "Přepsání",
    },
    "Other": {
        "rules": ["other", ":"],
        "cz_name": "Ostatní",
    },
}

# Charset definitions
CHARSET = {
    "numeric": "D",
    "loweralpha": "L",
    "upperalpha": "U",
    "special": "S",
    "mixedalpha": "L U",
    "loweralphanum": "L D",
    "upperalphanum": "U D",
    "mixedalphanum": "L U D",
    "specialnum": "D S",
    "loweralphaspecial": "L S",
    "upperalphaspecial": "U S",
    "mixedalphaspecial": "L U S",
    "loweralphaspecialnum": "L D S",
    "upperalphaspecialnum": "U D S",
    "all": "L U D S",
}
