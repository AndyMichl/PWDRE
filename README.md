# PWDRE - Password Rule Evaluation

Andrea Michlíková Bachelor's thesis: Experimental evaluation of methods for automated password-mangling rule generation

## Description

This repository contains tools for evaluating password-mangling rules, generating statistics, and visualizing results.

It works with tools Hashcat and zxcvbn for password recovery and scoring, and provides LaTeX outputs for detailed analysis.

GitHub Copilot was used to help generate comments in the code.

## Requirements

To run this tool, it is necessary to have the following components installed:

- **Python**: Version 3.12 or newer.
- **pip3**: For managing required Python packages. For example:
  - **jinja2**: For generating `.tex` files from templates.
  - **[zxcvbn](https://github.com/dropbox/zxcvbn)**: For password evaluation in one of the experiments.
- **[Hashcat](https://hashcat.net/hashcat/)**: For password cracking passwords.
- **Rule generation tools**: At least one of the tools for generating password-mangling rules. For example one of these:
  - [PACK](https://github.com/iphelix/pack/)
  - [Rulesfinder](https://github.com/synacktiv/rulesfinder)
  - [RuleForge](https://github.com/nesfit/RuleForge)
- **Dictionaries**: Password dictionaries are required for analysis.

### Installation

Install the required Python packages using:

```bash
pip3 install -r requirements.txt
```

## Usage

To run the main program with a configuration file:

```bash
python3 pwdre.py -c <config_file>
```

### Required Arguments

`-c <config_file>`: Specifies the file with configuration.

### Optional Arguments

`--delete-stats`: Deletes files in the results folder before execution.

`--delete-log`: Deletes the log file before execution.

`--no-log`: Disables logging.

`-l, --log-file <log_file>`: Specifies the log file to use.

## Configuration file manual

The configuration file is in YAML format and is used to set parameters for running the program.
It contains several sections that define general settings, inputs, statistics and programs.


### **Section `general`**

Contains general program settings.

| Key              | Description                                                          | Example of values        |
|------------------|----------------------------------------------------------------------|--------------------------|
| `wordlist`       | Path to the dictionary file.                                         | `path/to/wordlist.txt`   |
| `attack`         | The path to the file or folder containing the attacks files.         | `path/to/attack.txt`     |
| `target`         | The path to the file or folder containing the target files.          | `path/to/target.txt`     |
| `hashcat_folder` | The path to the folder with the rules applicable to Hashcat attacks. | `path/to/hashcat_folder/`|
| `stats_folder`   | The folder where results and statistics are stored.                  | `results/`               |
| `rules_file`     | Defines the name and location of the output rule file.               | `path/to/rules.rule`     |

---

To the value of the key `rules_file` can be add some placeholders.
It means that its value can look like `expe/<program>_<argsN>_<wordlist>.rule`.

| Placeholders | Description                                   |
|--------------|-----------------------------------------------|
| `<program>`  | Will be replaced by the name of the programme |
| `<argsN>`    | The order of the chosen argument.             |
| `<wordlist>` | Name of the input dictionary.                 |

---

### **Section `programs`**

Contains a list of programs to be run, including their parameters.

| Key    | Description                                    | Example of values             |
|--------|------------------------------------------------|-------------------------------|
| `name` | Name of the programme.                         | `PACK`                        |
| `run`  | Optional item, acts as a placeholder for args. | `python2 -u rulegen.py`       |
| `args` | List of arguments to be run with program. | `<run> <wordlist> -b <rules>` |

---

To the value of the key `args` can be add some placeholders.

| Placeholders | Description                                   |
|--------------|-----------------------------------------------|
| `<run>`      | General settings that can be common to multiple variants of running the program.  |
| `<wordlist>` | Name of the input dictionary from general section.      |
| `<rules>`    | Name of file with generated rules from general section. |

---

### **Section `stats`**

Defines which statistics to collect.

| Key                     | Description                                             | Example of value               |
|-------------------------|---------------------------------------------------------|--------------------------------|
| `time_passwords`        | Measuring the time it takes to crack passwords.         | `true`                         |
| `memory_passwords`      | Measuring the memory consumption of password cracking.  | `true`                         |
| `cpu_passwords`         | Measuring CPU usage during password cracking.           | `true`                         |
| `rules_passwords`       | Measuring the effectiveness of password cracking rules. | `true`                         |
| `recovered_guesses`     | Number of successfully cracked passwords.               | `true`                         |
| `zxcvbn_recovered`      | Password evaluation using zxcvbn.                       | `true`                         |
| `zxcvbn_score`          | Password scores by zxcvbn.                              | `true`                         |
| `analyze_wordlist`      | Analysis of dictionaries.                               | `true`                         |

Defines output paths for the `.tex`.

| Key                     | Description                                             | Example of value               |
|-------------------------|---------------------------------------------------------|--------------------------------|
| `time_passwords_file`   | Output file for LaTeX time statistics.                  | `time_passwords.tex`           |
| `memory_passwords_file` | Output file for LaTeX memory statistics.                | `memory_passwords.tex`         |
| `cpu_passwords_file`    | Output file for LaTeX CPU statistics.                   | `cpu_passwords.tex`            |
| `rules_passwords_file`  | Output file for LaTeX rules statistics.                 | `rules_passwords.tex`          |
| `recovered_guesses_file`| Output file for LaTeX recovered guesses statistics.     | `recovered_guesses.tex`        |
| `zxcvbn_recovered_file` | Output file for LaTeX zxcvbn recovered statistics.      | `zxcvbn_recovered.tex`         |
| `zxcvbn_score_file`     | Output file for LaTeX zxcvbn score statistics.          | `zxcvbn_score.tex`             |
| `analyze_wordlist_file` | Output file for LaTeX wordlist analysis.                | `analyze_wordlist.tex`         |

Defines output paths for the `.csv`.

| Key                     | Description                                             | Example of value               |
|-------------------------|---------------------------------------------------------|--------------------------------|
| `program_csv_file`      | CSV file for program statistics.                        | `program_stats.csv`            |
| `hashcat_csv_file`      | CSV file for Hashcat statistics.                        | `hashcat_stats.csv`            |
| `zxcvbn_score_csv_file` | CSV file for zxcvbn score statistics.                   | `zxcvbn_score_stats.csv`       |
| `zxcvbn_recovered_csv_file` | CSV file for zxcvbn recovered statistics.           | `zxcvbn_recovered_stats.csv`   |
| `wordlist_csv_file`     | CSV file for wordlist analysis.                         | `wordlist_stats.csv`           |

---

### **Section `input`**

Defines inputs such as dictionary sizes and rules. The value 0 is for an unmodified file.

| Key              | Description                                   | Example of value |
|------------------|-----------------------------------------------|------------------|
| `wordlist_size`  | List of dictionary sizes for rule generation. | `[1000, 5000, 0]`|
| `rules_size`     | List of rule sizes for attack with Hashcat.   | `[10, 50, 100]`  |

---

### **Example of a configuration file**

Configuration file to start dictionaries analysis:

```yaml
general:
  wordlist: dictionaries/
  stats_folder: results_dict/

stats:
  analyze_wordlist: True
```

Configuration file to run the RuleForge tool:

```yaml
general:
  wordlist: dictionaries/
  rules_file: rules/<program>_<argsN>_<wordlist>.rule

programs:
  - program: RF
    run: python3 programs/RuleForge.py --rulefile <rules> --representative combo
    args: 
      - <run> --wordlist <wordlist> --hac --distance_threshold 4 
      - ./programs/MDBSCAN/MDBSCAN/bin/Release/net7.0/MDBSCAN 2 3 <wordlist> | <run> --stdin

input:
  wordlist_size:
    - 5000
    - 0

stats:
  time_passwords: true
  rules_passwords: true
```

Configuration file to run only with Hashcat:

```yaml
general:
  attack: dictionaries/file.txt
  target: dictionaries/attack/
  hashcat_folder: hashcat_rules/

stats:
  recovered_guesses: true

input:
  rules_size:
    - 7500
    - 10000
```
