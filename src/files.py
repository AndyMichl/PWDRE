# Author: Andrea Michlíková - xmichl11

import os
import random
import shutil
import src.shared as shared


def save_to_file(file_path, data):
    """Saves data to a file."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(data)


def list_subdirectories(directory):
    """Return a list of subdirectories in the given directory."""
    try:
        return [os.path.join(directory, d) 
                for d in os.listdir(directory) if os.path.isdir(os.path.join(directory, d))]
    except FileNotFoundError:
        print(f"ERROR: Directory not found: {directory}")
        return []


def list_files_in_directory(directory, script_dir):
    """Returns a list of files in the given directory relative to script_dir."""
    try:
        return [os.path.relpath(os.path.join(directory, f), start=script_dir) 
                for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    except FileNotFoundError:
        print(f"ERROR: Directory not found: {directory}")
        return []


def count_lines_in_file(file_path):
    """Counts the number of lines in a file."""
    try:
        count = 0
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            count = sum(1 for line in file if line.strip())
            return count
    except FileNotFoundError:
        print(f"ERROR: File not found: {file_path}")
        return 0


def make_filepath(folder, filename):
    """Creates a file path and ensures the directory exists."""
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, filename)


##############################################################################################
def create_size_file(folder, file_basename, current_passwords, size):
    """Randomly selects a specified number of passwords and saves them to a file."""
    selected_pwd = random.sample(current_passwords, size)
    output = os.path.join(folder, f"{file_basename}_{size}.txt")

    if not os.path.exists(output):
        save_to_file(output, "\n".join(selected_pwd))
        print(f"Generated file: {output}")

    return {"name": output, "size": size}, selected_pwd


def process_sizes(file_path, passwords, sizes, max_size):
    """Processes a list of sizes and generates files with the specified number of passwords."""
    file_size = count_lines_in_file(file_path)
    file_basename = os.path.splitext(os.path.basename(file_path))[0]
    folder = os.path.join(os.path.dirname(file_path), "random_selected")
    wordlist_info = []
    for size in sizes:
        if size == 0:
            wordlist_info.append({"name": file_path, "size": max_size})
            continue
        if file_size < size:
            print(f"WARNING: Requested size {size} exceeds file size {file_size} in {file_path}.")
            continue

        info, passwords = create_size_file(folder, file_basename, passwords, size)
        wordlist_info.append(info)
    return wordlist_info


def load_passwords(file_path):
    """Loads passwords from a file, filtering out empty lines and comments."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            return [line.strip() for line in file if line.strip() and not line.startswith("#")]
    except (UnicodeDecodeError, FileNotFoundError) as e:
        print(f"ERROR: Reading file '{file_path}': {e}")
        return []


def validate_sizes(sizes):
    """Validates that sizes list is valid (non-negative integers)."""
    if not sizes or any(size < 0 for size in sizes):
        print("ERROR: sizes must be a list of non-negative integers.")
        return False
    return True


def select_passwords_from_file(file_path, sizes, max_size):
    """Selects passwords from a file based on the given sizes."""
    if not validate_sizes(sizes): return []

    sizes = sorted(sizes, reverse=True)
    passwords = load_passwords(file_path)
    
    if not passwords: return []

    return process_sizes(file_path, passwords, sizes, max_size)


##############################################################################################
def get_wordlist_info(wordlist_path):
    """Gets wordlist information based on the wordlist size from the config."""
    max_size = count_lines_in_file(wordlist_path)
    sizes = shared.CONFIG.input.wordlist_size

    if not sizes:
        return [{"name": wordlist_path, "size": max_size}]
    return select_passwords_from_file(wordlist_path, sizes, max_size)


def get_files(file_path):
    """Gets a list of files from a directory or a single file."""
    if os.path.isfile(file_path):
        return [file_path]
    elif os.path.isdir(file_path):
        file_list = [
            os.path.join(file_path, file_name)
            for file_name in os.listdir(file_path)
            if os.path.isfile(os.path.join(file_path, file_name)) and not file_name.startswith(".MDBSCANcache")
        ]
        if not file_list:
            raise ValueError(f"Directory '{file_path}' is empty.")
        return file_list


def create_rules_file_name(program, wordlist, i):
    """Generates a rules file name by replacing placeholders in the config template."""
    wl = os.path.splitext(os.path.basename(wordlist))[0]
    filename = (
        shared.CONFIG.general.rules_file.replace("<program>", program.name)
        .replace("<wordlist>", wl)
        .replace("<argsN>", str(i))
    )
    return filename


def get_rules_list():
    """Creates a list of rule files based on the config and wordlists."""
    rules_files = []
    if shared.CONFIG.general.hashcat_folder != "":
        folder = os.path.join(shared.SCRIPT_DIR, shared.CONFIG.general.hashcat_folder)
        subdirectories = list_subdirectories(folder)
        if subdirectories:
            for subdir in subdirectories:
                for file in list_files_in_directory(subdir, shared.SCRIPT_DIR):
                    rules_files.append(file)
            return rules_files
        for file in list_files_in_directory(folder, shared.SCRIPT_DIR):
            rules_files.append(file)
    else:
        # If no folder is specified, generate rules from programs and wordlists
        for wordlist in shared.WORDLIST_LIST:
            for program in shared.CONFIG.programs:
                for i, arg in enumerate(program.args):
                    rule_file = create_rules_file_name(program, wordlist, i)
                    rules_files.append(rule_file)
    return rules_files


def create_temporary_file(file, limit):
    """Creates a temporary file with the first 'limit' lines from a file."""
    temp_file_path = make_filepath("temp/", f"{os.path.splitext(os.path.basename(file))[0]}_{limit}.txt")

    file_size = count_lines_in_file(file)
    if file_size < limit:
        print(f"WARNING: The file '{file}' has only {file_size} lines, which is less than the limit of {limit}.")
        return None

    with open(file, "r", encoding="utf-8") as wordlist, open(temp_file_path, "w", encoding="utf-8") as temp_file:
        temp_file.writelines(line for _, line in zip(range(limit), wordlist))

    return temp_file_path


##########################################################################
def delete_stats_folder(folder):
    """Deletes all files in the statistics folder after user confirmation."""
    if os.path.exists(folder):
        if any(os.scandir(folder)):  # Checks if the folder contains any files or subfolders
            confirm = (input(f"The folder '{folder}' contains files. Do you really want to delete them? [Y/N]: ").strip().lower())
            if confirm == "y":
                shutil.rmtree(folder)
                print("Deletion completed.")
                os.makedirs(folder, exist_ok=True)
            else:
                print("Deletion canceled.")


def delete_log_file(log_file):
    """Deletes the log file after user confirmation."""
    if os.path.exists(log_file):
        confirm = (
            input(f"The file '{log_file}' exists. Do you really want to delete it? [Y/N]: ").strip().lower())
        if confirm == "y":
            os.remove(log_file)
            print("Deletion completed.")
        else:
            print("Deletion canceled.")
