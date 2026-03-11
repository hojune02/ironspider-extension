#!/usr/bin/env python3
"""Generate E1 SLOC growth bar chart for the replication report."""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# Data from E1 firmware analysis
versions = ['v3.0.39\n(May 2019)', 'v3.1.7\n(Jul 2019)',
            'v3.09.04\n(Mar 2022)', 'v4.02.13\n(Mar 2023)']
total_sloc = [13188, 13472, 36544, 39007]
js_sloc = [12868, 13150, 35994, 38444]
php_sloc = [320, 322, 550, 563]
complexity = [4529, 4574, 11379, 11974]

x = np.arange(len(versions))
width = 0.35

fig, ax1 = plt.subplots(figsize=(7, 4))

# Stacked bar: JS + PHP = Total SLOC
bars_js = ax1.bar(x - width/2, js_sloc, width, label='JavaScript SLOC',
                  color='#2196F3', edgecolor='white', linewidth=0.5)
bars_php = ax1.bar(x - width/2, php_sloc, width, bottom=js_sloc,
                   label='PHP SLOC', color='#FF9800', edgecolor='white',
                   linewidth=0.5)

# Complexity bars
bars_cx = ax1.bar(x + width/2, complexity, width, label='Cyclomatic Complexity',
                  color='#4CAF50', edgecolor='white', linewidth=0.5)

ax1.set_ylabel('Count')
ax1.set_xticks(x)
ax1.set_xticklabels(versions, fontsize=9)
ax1.set_title('WAGO WBM Codebase Growth (E1 Replication)')
ax1.legend(loc='upper left', fontsize=8)
ax1.set_ylim(0, 45000)

# Add value labels on top of total SLOC bars
for i, v in enumerate(total_sloc):
    ax1.text(x[i] - width/2, v + 500, f'{v:,}', ha='center', va='bottom',
             fontsize=7.5, fontweight='bold')
for i, v in enumerate(complexity):
    ax1.text(x[i] + width/2, v + 500, f'{v:,}', ha='center', va='bottom',
             fontsize=7.5, fontweight='bold')

# Growth annotation
ax1.annotate('+171% SLOC', xy=(2, 36544), xytext=(1.3, 40000),
             fontsize=8, color='red',
             arrowprops=dict(arrowstyle='->', color='red', lw=1.2))

ax1.grid(axis='y', alpha=0.3, linestyle='--')
plt.tight_layout()
plt.savefig('e1_sloc_growth.pdf', bbox_inches='tight', dpi=300)
plt.savefig('e1_sloc_growth.png', bbox_inches='tight', dpi=150)
print('Saved e1_sloc_growth.pdf and e1_sloc_growth.png')
