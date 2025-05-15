# Author: Andrea Michlíková - xmichl11

from collections import defaultdict
import statistics
import math
import string
from src.log import rules_to_csv, is_file_record_in_csv, wordlist_to_csv
from src.files import get_rules_list
import src.shared as shared

def analyze_rules():
    """Analyzes rule files to count occurrences of specific rules."""
    rules_files = get_rules_list()
    rule_order = shared.RULE_ORDER.keys()
    rule_counts = defaultdict(int, {rule: 0 for rule in rule_order})

    for rule_file in rules_files:
        line_lengths = []
        if is_file_record_in_csv(shared.CONFIG.stats.rules_csv_file, "rule_file", rule_file):
            continue
        with open(rule_file, "r", encoding="utf-8") as file:
            for line in file:
                # Split the line by spaces to get individual rules
                if not line or line[0] == "#":
                    continue
                rules = line.strip().split()
                line_lengths.append(len(rules))
                for rule in rules:
                    # Count only the first character of each rule
                    general_rule = rule[:1]
                    if general_rule not in rule_order:
                        rule_counts['other'] += 1
                        continue
                    rule_counts[general_rule] += 1

        rules_to_csv(rule_file, rule_order, rule_counts)

#############################################################
def find_charset(password):
    """Checks for the presence of lowercase, uppercase, digits, and special characters."""
    has_lower = has_upper = has_digit = has_special = False
    for c in password:
        if c.islower():
            has_lower = True
        elif c.isupper():
            has_upper = True
        elif c.isdigit():
            has_digit = True
        elif c in string.punctuation:
            has_special = True

        if has_lower and has_upper and has_digit and has_special:
            break
    is_ascii = password.isascii()
    return has_lower, has_upper, has_digit, has_special, is_ascii


def calculate_char_amount(has_lower, has_upper, has_digit, has_special):
    """Calculates the total number of possible characters based on the character sets used."""
    R = 26 if has_lower else 0
    R += 26 if has_upper else 0
    R += 10 if has_digit else 0
    R += 32 if has_special else 0
    return R


def calculate_entropy(len, has_lower, has_upper, has_digit, has_special):
    """Calculates the entropy of a password."""
    char_amount = calculate_char_amount(has_lower, has_upper, has_digit, has_special)
    if char_amount <= 0:
        return 0
    return math.log2(char_amount) * len


def get_charset(has_lower, has_upper, has_digit, has_special):
    """Maps the combination of character sets to a specific charset name."""
    charset_map = {
        (True, False, False, False): "numeric",
        (False, True, False, False): "loweralpha",
        (False, False, True, False): "upperalpha",
        (False, False, False, True): "special",
        (False, True, True, False): "mixedalpha",
        (True, True, False, False): "loweralphanum",
        (True, False, True, False): "upperalphanum",
        (True, True, True, False): "mixedalphanum",
        (True, False, False, True): "specialnum",
        (False, True, False, True): "loweralphaspecial",
        (False, False, True, True): "upperalphaspecial",
        (False, True, True, True): "mixedalphaspecial",
        (True, True, False, True): "loweralphaspecialnum",
        (True, False, True, True): "upperalphaspecialnum",
    }

    charset = charset_map.get((has_digit, has_lower, has_upper, has_special), "all")
    return charset


def analyze_password(password, charset_counts):
    """Analyzes a single password, determines its length, entropy, and character set."""
    length = len(password)

    # Výpočet entropie hesla
    digit, lower, upper, special, is_ascii = find_charset(password)
    entropy = calculate_entropy(length, digit, lower, upper, special)
    charset = get_charset(digit, lower, upper, special)

    charset_counts[charset] += 1
    return length, entropy, is_ascii


def analyze_wordlist():
    """Analyzes all wordlists in the shared configuration."""
    for wl_path in shared.WORDLIST_LIST:
        if is_file_record_in_csv(shared.CONFIG.stats.wordlist_csv_file, "wordlist", wl_path):
            return
        wl_size = 0
        lengths = []
        entropies = [] 
        entropy_above = 0  # Number of passwords with entropy above 75
        charset_counts = defaultdict(int, {key: 0 for key in shared.CHARSET.keys()})
        ascii = 0

        with open(wl_path, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                line = line.rstrip("\n")
                wl_size += 1

                len, entropy, is_ascii = analyze_password(line, charset_counts)
                lengths.append(len)
                entropies.append(entropy)

                if is_ascii:
                    ascii += 1

                if entropy >= 75:
                    entropy_above += 1

        median_len = round(statistics.median(lengths) if lengths else 0)
        avg_len = round(statistics.mean(lengths) if lengths else 0, 2)

        avg_entropy = round(statistics.mean(entropies) if entropies else 0, 2)

        wordlist_to_csv(
            wl_path,
            wl_size,
            avg_len,
            median_len,
            avg_entropy,
            entropy_above,
            ascii,
            charset_counts,
        )
