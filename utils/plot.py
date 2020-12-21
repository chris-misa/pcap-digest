#!/usr/bin/env python
import sys
import numpy as np
import matplotlib.pyplot as plt

DATA_FILE="../OUTPUTS/combined.out"
PLOT_FILE="../OUTPUTS/plot.pdf"
TITLE=sys.argv[1] if len(sys.argv) == 2 else ""

cols = {
    "time" : 0,
    "srcs" : 1,
    "dsts" : 2,
    "srcdsts" : 3,
    "srcdstlens" : 4,
    "srcdports" : 5,
    "srcdstsports" : 6,
}

data = np.loadtxt(DATA_FILE, delimiter=",", skiprows=1, usecols=cols.values())

fig = plt.figure(figsize=(7,3))
ax = fig.add_subplot(111)
ax.grid()

for k, v in cols.items():
    if k != "time":
        ax.plot(data[:,cols["time"]], data[:,v], label=k)
ax.legend()

plt.title(TITLE)
plt.yscale("log")
plt.tight_layout(pad=0.1)
plt.savefig(PLOT_FILE)

