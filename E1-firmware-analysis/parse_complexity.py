#!/usr/bin/env python3
import json
import sys

total_sloc = 0
total_complexity = 0

# Read the JSON file (one JSON object per line or concatenated)
with open(sys.argv[1], 'r') as f:
    content = f.read()
    
# Try to parse as single JSON first
try:
    data = json.loads(content)
    if 'reports' in data:
        total_sloc += data['reports'][0]['aggregate']['sloc']['logical']
        total_complexity += data['reports'][0]['aggregate']['cyclomatic']
except:
    # Parse line by line
    for line in content.split('\n'):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            if 'reports' in data:
                total_sloc += data['reports'][0]['aggregate']['sloc']['logical']
                total_complexity += data['reports'][0]['aggregate']['cyclomatic']
        except:
            pass

print(f"Total JS Logical SLOC: {total_sloc}")
print(f"Total JS Cyclomatic Complexity: {total_complexity}")
