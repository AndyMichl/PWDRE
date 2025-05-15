# Author: Andrea Michlíková - xmichl11

import os
import csv
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict
import src.shared as shared
from src.files import count_lines_in_file, save_to_file


def program_tex():
    """Generates LaTeX graphs for program statistics."""
    # Path to the CSV file containing program statistics
    csv_path = shared.CONFIG.stats.program_csv_file

    # Initialize the Jinja2 environment and load the template
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("program_graph.tex.jinja")

    # Iterate over different statistic types
    for stat_type in ["memory", "time", "cpu", "rules"]:
        if stat_type == "memory" and not shared.CONFIG.stats.memory_passwords:
            continue
        if stat_type == "time" and not shared.CONFIG.stats.time_passwords:
            continue
        if stat_type == "cpu" and not shared.CONFIG.stats.cpu_passwords:
            continue
        if stat_type == "rules" and not shared.CONFIG.stats.rules_passwords:
            continue
        
        
        grouped = defaultdict(list)

        # Open the CSV file and read its content
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            # Process each row in the CSV file
            for row in reader:
                size = int(row['size'])

                # Skip rows with sizes not in the allowed wordlist sizes
                if size not in shared.CONFIG.input.wordlist_size:
                    if ((count_lines_in_file(row["wordlist"]) != size)
                        or (0 not in shared.CONFIG.input.wordlist_size)):
                        print(f"TEX PROGRAM: Skipping size {size} for wordlist {row['wordlist']}")
                        continue

                # Group data by program and run index
                key = (row['program'], int(row['run_index']))
                grouped[key].append((int(row["size"]), float(row[stat_type])))

        # Generate the output filename based on the statistic type
        filename = getattr(shared.CONFIG.stats, f"{stat_type}_passwords_file")
        label_y = {"memory": "Paměť [MB]", "time": "Čas [s]", "cpu": "Průměr CPU v \\%", "rules": "Počet pravidel"}[stat_type]
        title_type = {"memory": "PAMĚŤ", "time": "ČAS", "cpu": "CPU", "rules": "PRAVIDLA"}[stat_type]
        title = f"Generování pravidel - {title_type}"

        plots = []  # List to store plot data

        # Process grouped data to create plots
        for i, ((program, run_index), rows) in enumerate(grouped.items()):
            rows = sorted(rows, key=lambda r: r[0])  # Sort rows by size
            points = [(size, value, "") for size, value in rows]  # Prepare points for the plot
            plots.append({
                "legend": f"{program} {run_index}",
                "points": points,
                "comment": f"{program} {run_index}"
            })

        # Render the LaTeX content using the template
        content = template.render(
            labels={
                "title": title,
                "xlabel": "Počet hesel",
                "ylabel": label_y,
            },
            plots=plots,
        )

        # Save the rendered content to a file
        save_to_file(filename, content)
        print(f"Program LaTeX file saved to {filename}")


def hashcat_tex():
    """Generates LaTeX graphs for Hashcat statistics."""
    # Path to the CSV file containing Hashcat statistics
    csv_path = shared.CONFIG.stats.hashcat_csv_file

    # Initialize the Jinja2 environment and load the template
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("program_graph.tex.jinja")

    # Open the CSV file and read its content
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        grouped = defaultdict(list)

        # Process each row in the CSV file
        for row in reader:
            size = int(row['rule_size'])

            # Skip rows with sizes not in the allowed rule sizes
            if size not in shared.CONFIG.input.rules_size:
                if (count_lines_in_file(row["rule_file"]) != size
                    or 0 not in shared.CONFIG.input.rules_size):
                    print(f"TEX HASHCAT: Skipping size {size} for rule_file {row['rule_file']}")
                    continue

            # Group data by rule file
            grouped[row['rule_file']].append(row)

    # Get filename for the LaTeX file and define the title for the graph
    filename = shared.CONFIG.stats.recovered_guesses_file
    title = "Prolomená hesla"

    plots = []  # List to store plot data

    # Process grouped data to create plots
    for i, (rule_file, rows) in enumerate(grouped.items()):
        # Sort rows by rule size
        rows = sorted(rows, key=lambda r: int(r['rule_size']))

        # Prepare points for the plot
        points = [(int(r['rule_size']) * int(r['attack_size']),
                   float(r['recovered']),
                   f"% progress = {int(r['progress'])}")for r in rows]
        file = os.path.basename(rule_file).replace("_", "\\_")

        # Append plot data
        plots.append({"legend": file, "points": points, "comment": file})

    # Render the LaTeX content using the template
    content = template.render(
        labels={
            "title": title,
            "xlabel": "Počet vyzkoušených možností",
            "ylabel": "Prolomených hesel \\%",
        },
        plots=plots,
    )

    # Save the rendered content to a file
    save_to_file(filename, content)
    print(f"Hashcat LaTeX file saved to {filename}")


def zxcvbn_score_tex():
    """Generates LaTeX bar graphs for zxcvbn score distribution."""
    # Path to the CSV file containing zxcvbn score statistics
    csv_path = shared.CONFIG.stats.zxcvbn_score_csv_file

    # Initialize the Jinja2 environment and load the template
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("bar_graph.tex.jinja")

    plots = []  # List to store plot data
    max_y = 0  # Variable to track the maximum Y value for the graph

    # Open the CSV file and read its content
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        # Process each row in the CSV file
        for row in reader:
            file_name = row['file_name']
            recovered = float(row['recovered'])

            # Prepare points for the bar graph (score distribution)
            points = [(i, int(row[f"score_{i}"])) for i in range(5)]
            max_y = max(max_y, max(count for _, count in points))

            # Append plot data for the current file
            plots.append({"legend": file_name.replace("_", "\\_"),
                          "points": points,
                          "recovered": recovered})

    # Define labels and title for the graph
    title = "Rozložení skóre prolomených hesel"
    ylabel = "Počet hesel"
    xlabel = "Skóre (0-4)"
    # Zaokrouhli maximální hodnotu Y na nejbližší tisíce
    ymax = ((max_y + 999) // 1000) * 1000

    # Render the LaTeX content using the template
    content = template.render(
        labels={"title": title, "xlabel": xlabel, "ylabel": ylabel},
        plots=plots,
        data={"ymax": ymax}
    )

    # Save the rendered content to a file
    filename = shared.CONFIG.stats.zxcvbn_score_file
    save_to_file(filename, content)
    print(f"Zxcvbn LaTeX file saved to {filename}")


def zxcvbn_recovered_tex():
    """Generates LaTeX bar graphs for password recovery difficulty."""
    # Path to the CSV file containing zxcvbn recovered statistics
    csv_path = shared.CONFIG.stats.zxcvbn_recovered_csv_file

    # Initialize the Jinja2 environment and load the template
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("bar_graph.tex.jinja")

    # Open the CSV file and read its content
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        grouped = defaultdict(list)

        # Process each row in the CSV file
        for row in reader:
            grouped[row['file_name']].append(row)

    # Define the output filename and graph title
    filename = shared.CONFIG.stats.zxcvbn_recovered_file
    title = "Náročnost prolomení hesel"

    plots = []  # List to store plot data
    max_y = 0  # Variable to track the maximum Y value for the graph

    # Process grouped data to create plots
    for i, (file_name, rows) in enumerate(grouped.items()):
        # Sort rows by the logarithm of guesses
        rows = sorted(rows, key=lambda r: float(r['guesses_log10']))

        # Prepare points for the bar graph
        points = [(float(r['guesses_log10']), int(r['n'])) for r in rows]
        max_y = max(max_y, max(int(r['n']) for r in rows))  # Update max_y

        # Append plot data for the current file
        plots.append({"legend": file_name.replace("_", "\\_"),
                      "points": points,
                      "recovered": float(rows[0]['recovered'])})

    # Round the maximum Y value to the nearest thousand for better graph scaling
    ymax = ((max_y + 999) // 1000) * 1000

    # Render the LaTeX content using the template
    content = template.render(
        labels={"title": title, "xlabel": "Náročnost $10^x$", "ylabel": "Počet hesel"},
        plots=plots,
        data={"ymax": ymax},  # Přidej ymax do dat pro šablonu
    )

    # Save the rendered content to a file
    save_to_file(filename, content)
    print(f"Zxcvbn recovered LaTeX file saved to {filename}")


def program_hashcat_tex_table():
    """Generates LaTeX tables for Program and Hashcat statistics."""
    # Paths to the CSV files
    hashcat_csv_path = shared.CONFIG.stats.hashcat_csv_file
    program_csv_path = shared.CONFIG.stats.program_csv_file

    # Load the LaTeX template
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("table.tex.jinja")  # Template for tables

    # Load data from the Hashcat CSV file
    hashcat_data = {}
    with open(hashcat_csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row['rule_file']  # Use the rule file as the key
            hashcat_data[key] = {
                "recovered": float(row['recovered']),  # Percentage of recovered passwords
            }

    # Load data from the program CSV file and combine it with Hashcat data
    program_data = defaultdict(list)
    with open(program_csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            program = row['program']  # Program name
            rule_file = row['rule_file']  # Rule file name

            # Skip if the rule file is not in the Hashcat data
            if rule_file not in hashcat_data:
                continue

            # Combine data from both CSV files
            program_data[program].append((
                row['run_index'],
                float(row['time']),
                float(row['memory']),
                int(row['rules']),
                hashcat_data.get(rule_file, {}).get("recovered", 0.0)
            ))

    content = ""  # Initialize the content for the LaTeX file

    # Generate a table for each program
    for program, table_data in program_data.items():
        # Render the table content using the template
        content += f"% {program}\n"  # Add a comment with the program name
        content += template.render(data={"points": table_data})  # Render the table
        content += "\n\n"

    # Save the combined content to a single LaTeX file
    filename = os.path.join(shared.CONFIG.general.stats_folder, "hashcat_table.tex")
    save_to_file(filename, content)
    print(f"Hashcat LaTeX table saved to {filename}")


def rule_to_tex(rule):
    """Converts a rule to LaTeX form."""
    tex_rule = rule  # Start with the original rule

    # Handle special characters that need escaping or specific formatting in LaTeX
    if rule in ["{", "}"]:
        tex_rule = f"\\{rule}"
    elif rule == "$":
        tex_rule = f"\\{rule}X"
    elif rule == "^":
        tex_rule = "\\textasciicircum X"
    elif rule == "@":
        tex_rule = "\\texttt{@}X"
    elif rule in ["[", "]"]:
        tex_rule = f"${rule}$"
    elif rule in ["T", "p", "D", "'", "z", "Z"]:
        tex_rule += "N"
    elif rule in ["i", "o"]:
        tex_rule += "NX"
    elif rule in ["x", "O"]:
        tex_rule += "NM"
    elif rule == "s":
        tex_rule += "XY"  
    elif rule == "other":
        tex_rule = ""     
    return tex_rule


def rules_tex_table():
    """Generates LaTeX tables for rule statistics."""
    # Path to the CSV file containing rule statistics
    rules_csv_path = shared.CONFIG.stats.rules_csv_file

    # Load the LaTeX template
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("rule_table.tex.jinja")

    # Prepare data structures for the templates
    data_order = defaultdict(dict)  # Dictionary for rule_file and individual rules
    data_group = defaultdict(lambda: defaultdict(int))  # Dictionary for rule_file and grouped rules
    rule_files = []  # List of rule files
    rule_names = {}  # Mapping of rules to their names
    group_names = {}  # Mapping of groups to their names
    group_rules = {}  # Mapping of groups to their rules

    # Read the CSV file and process its content
    with open(rules_csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rule_file = row['rule_file'].replace("_", "\\_")  # Format rule file for LaTeX
            rule_files.append(os.path.basename(rule_file))  # Add rule file to the list

            # Process each rule in the row
            for rule, value in row.items():
                tex_rule = rule_to_tex(rule)  # Convert the rule to LaTeX format
                if rule == "rule_file":
                    continue  # Skip the rule_file column

                # Add data for ordered rules
                data_order[tex_rule][rule_file] = int(value)

                # Get the English and Czech names for the rule
                english_name, czech_name = shared.RULE_ORDER.get(rule, ("Unknown", "Neznámé"))
                rule_names[tex_rule] = czech_name  # Store the Czech name (or English if needed)

                # Add data for grouped rules
                for group_name, group_data in shared.RULE_GROUPS.items():
                    if rule in group_data['rules']:
                        data_group[group_name][rule_file] += int(value)

    # Process group names and their rules
    for group_name, group_data in shared.RULE_GROUPS.items():
        tex_rules = [rule_to_tex(rule) for rule in group_data['rules']]  # Convert rules to LaTeX
        group_rules[group_name] = ", ".join(tex_rules)  # Combine rules into a single string
        group_names[group_name] = group_data['cz_name']  # Use the Czech name for the group

    # Generate the LaTeX content for the grouped or ordered rules table
    content += template.render(
        rule_order=shared.CONFIG.stats.analyze_rules,
        rule_group=shared.CONFIG.stats.analyze_rules,
        header=rule_files,
        header_size=len(rule_files),
        data_group={group_name: data_group[group_name] for group_name in shared.RULE_GROUPS},
        data_order=data_order,
        group_name=group_names,
        rule_name=rule_names)

    # Save the generated content to a LaTeX file
    filename = shared.CONFIG.stats.analyze_rules_file
    save_to_file(filename, content)
    print(f"LaTeX table saved to {filename}")


def wordlist_tex_table():
    """Generates LaTeX tables for wordlist statistics."""
    # Path to the CSV file containing wordlist statistics
    csv_path = shared.CONFIG.stats.wordlist_csv_file

    # Load the LaTeX template
    env = Environment(loader=FileSystemLoader("templates"))
    template_group = env.get_template("wordlist_table.tex.jinja")

    # Initialize data structures
    data = []  # Data for the first table
    charset_data = defaultdict(dict)  # Data for the second table (charset × wordlist)
    wordlists = []  # List of wordlists (for table headers)

    # Open the CSV file and read its content
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            file = os.path.basename(row['wordlist']).replace("_", "\\_")
            wl_size = int(row['size'])
            entropy_above = f"{(int(row['entropy_above']) / wl_size) * 100:.2f}\\%"
            ascii = f"{(int(row['ascii']) / wl_size) * 100:.2f}\\%"
            
            data.append([
                file,
                wl_size,
                row['avg_len'],
                row['median_len'],
                row['avg_entropy'],
                entropy_above,
                ascii,
            ])

            # Add the wordlist to the list of headers
            wordlists.append(file)

            # Process charset counts for the second table
            for charset, count in row.items():
                if charset in shared.CHARSET.keys(): 
                    cz_charset = shared.CHARSET[charset] 
                    charset_data[cz_charset][file] = int(count)

    # Generate the LaTeX content for the table
    content = template_group.render(
        data=data,
        header=wordlists,
        charset_data=charset_data,
    )

    # Save the generated content to a LaTeX file
    filename = shared.CONFIG.stats.analyze_wordlist_file
    save_to_file(filename, content)
    print(f"LaTeX table saved to {filename}")
