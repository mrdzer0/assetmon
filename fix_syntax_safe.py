import re

file_path = 'web/templates/project_detail.html'

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
skip_next = False

for i, line in enumerate(lines):
    if skip_next:
        skip_next = False
        continue

    # Fix Line 244/245 specific accumulation
    if "status_counts['3xx'] }" in line and not "}}" in line:
        # Found the broken line
        parts = line.split("status_counts['3xx'] }")
        indent = parts[0]
        new_lines.append(f"{indent}status_counts['3xx'] }},\n")
        # The next line is likely the garbage "}," so we skip it if it looks like that
        if i + 1 < len(lines) and lines[i+1].strip() == "},":
            skip_next = True
    elif "status_counts['3xx']" in line and "}}" in line and not line.strip().endswith(","):
         # It might be fixed but missing comma
         new_lines.append(line.rstrip() + ",\n")
    else:
        new_lines.append(line)

# Global fix for { { space
final_lines = []
for line in new_lines:
    line = line.replace("{ {", "{{").replace("} }", "}}")
    final_lines.append(line)

with open(file_path, 'w') as f:
    f.writelines(final_lines)

print("Fixed syntax errors safely.")
