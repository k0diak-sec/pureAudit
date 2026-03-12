oui = {}

with open("oui.txt") as file:
    for line in file:
        if "(hex)" in line:
            parts = line.split("\t")
            prefix = parts[0].replace("(hex)", "").strip()
            company = parts[-1].strip()
            oui[prefix] = company

# Write to src/buildOuiDatabase.py
with open("../src/buildOuiDatabase.py", "w") as out:
    out.write("# Auto-generated OUI database from IEEE\n")
    out.write("# Source: https://standards-oui.ieee.org/oui/oui.txt\n\n")
    out.write("OUI_DATABASE = {\n")
    for prefix, company in oui.items():
        safe = company.replace('"', '\\"')
        out.write(f'    "{prefix}": "{safe}",\n')
    out.write("}\n")

print(f"Done. {len(oui)} entries written to ../src/buildOuiDatabase.py")