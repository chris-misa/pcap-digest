#!/usr/bin/env python
import sys
import numpy as np
import matplotlib.pyplot as plt

if len(sys.argv) != 4:
    print("Usage: <data file in> <plot file out> <plot title>")
    sys.exit()

DATA_FILE=sys.argv[1]
PLOT_FILE=sys.argv[2]
TITLE=sys.argv[3]

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

ax.set_xlabel("Time (s)")
ax.set_ylabel("Count")

plt.title(TITLE)
plt.yscale("log")
plt.tight_layout(pad=0.1)
plt.savefig(PLOT_FILE)

