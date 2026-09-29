#!/usr/bin/env python3
import json
import re
import os

# Go to repo root
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

with open("tests/integration/distros.json") as f:
    distros = json.load(f)

badges = " ".join(d["badge"] for d in distros)
ci_badge = "[![Integration Tests](https://github.com/Jekuper/crystal_hammer/actions/workflows/integration.yml/badge.svg)](https://github.com/Jekuper/crystal_hammer/actions/workflows/integration.yml)"

replacement = f"<!-- BADGES_START -->\n{ci_badge}\n<br>\n{badges}\n<!-- BADGES_END -->"

with open("README.md", "r") as f:
    content = f.read()

new_content = re.sub(r"<!-- BADGES_START -->.*?<!-- BADGES_END -->", replacement, content, flags=re.DOTALL)

with open("README.md", "w") as f:
    f.write(new_content)

print("README.md badges synchronized with distros.json successfully.")