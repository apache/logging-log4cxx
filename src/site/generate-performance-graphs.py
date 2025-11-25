#!/usr/bin/env python3
import re
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

class Test:
	def __init__(self):
		self.benchmark = None
		self.threads = None
		self.time = None
		self.cpu = None
		self.iterations = None
		self.cpu = None
		self.formatter = None
	

input_markdown_file = 'markdown/performance.md'
regex_patterns = [ 
#r"Appending (.*) using (MessageBuffer), pattern: \\%m\\%n$"
#                , r"Appending (.*) using (FMT), pattern: \\%m\\%n$"
#               , r"Appending (.*) using (MessageBuffer), pattern: \\%m\\%n/threads"
#               , r"Appending (.*) using (FMT), pattern: \\%m\\%n/threads"
	r"Appending (.*) using (MessageBuffer|FMT), pattern: \\%m\\%n(\/threads:(\d+) | )\| (\d+) ns \| (\d+) ns \| (\d+)"
                ]

def extract_test_from_line(line: str) -> Test:
	ret = Test()
	found = False

	for pattern in regex_patterns:
		value_match = re.search(pattern, line)

		if not value_match:
			continue

		found = True
		ret.benchmark = value_match.group(1)
		ret.formatter = value_match.group(2)
		if value_match.group(4) is None:
			ret.threads = 1
		else:
			ret.threads = int(value_match.group(4))
		ret.time = int(value_match.group(5))
		ret.cpu = int(value_match.group(6))
		ret.iterations = int(value_match.group(7))

	if not found:
		return None
	return ret

regex_thread_patterns = [
	r"Appending (.*) using (MessageBuffer), pattern: \\%m\\%n\/threads:(\d+) | (\d+) ns | (\d+) ns | (\d+)"
]

data = {'MessageBuffer': {}
         , 'FMT': {}
         }
line_type = {'MessageBuffer': '--'
            , 'FMT': '-.'
            }
all_results = []

# Extract the data
title = 'Appending'
image_file_name = 'images/Appending.png'

value_regex_pattern = r" *([0-9]+) ns"
with open(input_markdown_file, "r") as file:
	header_found = False
	separator_found = False
	for line in file:
		if header_found and separator_found:
			# A valid table data row (starts and ends with '|')
			if not (line.strip().startswith('|') and line.strip().endswith('|')):
				break

			result = extract_test_from_line(line.strip())
			if not result:
				continue
			all_results.append(result)
		elif " Benchmark " in line:
			header_found = True
		elif header_found and "----" in line:
			separator_found = True
		else:
			header_found = False

if len(data) < 2:
	raise ValueError(f"Benchmark data not found in {input_markdown_file}")

# Create the bar chart
#fig, ax = plt.subplots(figsize=(8, 6)) # Optional: set figure size
#for formatter, item_time in data.items():
#	message_types = item_time.keys()
#	time_values = item_time.values()
#	ax.plot(message_types, time_values, label=formatter, linestyle=line_type[formatter])

x = np.arange(10)  # the label locations
width = 0.25  # the width of the bars
multiplier = 0
fig, ax = plt.subplots(layout='constrained')
grouped_by_benchmark = defaultdict(list)
grouped_by_benchmark_threads = defaultdict(list)
grouped_by_formatter = defaultdict(list)
for result in all_results:
	if result.threads == 1:
		grouped_by_benchmark[result.benchmark].append(result)
	else:
		grouped_by_benchmark_threads[result.benchmark].append(result)
	grouped_by_formatter[result.formatter].append(result)

x_ticks=[]
for formatter, data in grouped_by_formatter.items():
	tup_data = tuple([o.time for o in data])
	print(f"tup: {tup_data} formatter: {formatter}")
	offset = width * multiplier
	rects = ax.bar(x + offset, tup_data, width, label=formatter)
	#ax.bar_label(rects, padding=3)
	multiplier += 1
	x_ticks.append(data[0].benchmark)

ax.set_xticks(x + width, x_ticks )
ax.legend(ncols=2)

# Add chart title and axis labels
#ax.legend()
ax.set_title(title, fontsize=14)
ax.set_xlabel('Message content', fontsize=12)
ax.set_ylabel('Time (ns)', fontsize=12)

# Improve layout and remove top/right spines for cleaner look
ax.spines['right'].set_visible(False)
ax.spines['top'].set_visible(False)
plt.tight_layout()

# Save the graph as a PNG file
plt.savefig(image_file_name)
