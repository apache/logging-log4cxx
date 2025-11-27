
// Get the DOM container for the plot
var containerDOM = document.getElementById('appending_a_log_message_plot');
if (!containerDOM) {
	throw new Error("Could not find 'appending_a_log_message_plot' element");
}
var myChart = echarts.init(containerDOM, null, { renderer: 'canvas' });


// Find the benchmark html table
var benchmark_data = null;
var element = document.getElementById('benchmark_data_marker');
while (element && element.tagName) {
	if (element.tagName === 'TABLE') {
		benchmark_data = element;
		break;
	}
	element = element.nextElementSibling;
}
if (!benchmark_data) {
	throw new Error("Could not find benchmark data");;
}

// Identify the benchmark tests to be included on the plot
var benchmark_pattern = [];
benchmark_pattern.push(new RegExp("Appending (.*) using ([A-Za-z]+), pattern: \\%m\\%n$"));
benchmark_pattern.push(new RegExp("Async, Sending (.*) using ([A-Za-z <]+)$"));
const value_regex_pattern = new RegExp("([0-9]+) ns")

// Extract the data
var plot_data = new Map();
var xAxisLabels = [];
for (let i = 0; i < benchmark_data.rows.length; ++i) {
	const columns = benchmark_data.rows[i].cells;
	if (2 < columns.length) {
		const value_match = value_regex_pattern.exec(columns[1].innerText);
		if (value_match && 1 < value_match.length) {
			for (let rIndex = 0; rIndex < benchmark_pattern.length; ++rIndex) {
				const benchmark_match = benchmark_pattern[rIndex].exec(columns[0].innerText);
				if (benchmark_match && 2 < benchmark_match.length) {
					if (!xAxisLabels.includes(benchmark_match[1])) {
						xAxisLabels.push(benchmark_match[1]);
					}
					var keyValueMap = plot_data.get(benchmark_match[2]);
					if (!keyValueMap) {
						keyValueMap = new Map();
						plot_data.set(benchmark_match[2], keyValueMap);
					}
					keyValueMap.set(benchmark_match[1], value_match[1]);
				}
			}
		}
	}
}

// Generate a series for each legend
var legend_data = [];
var series_data = [];
for (const [key, keyValueMap] of plot_data.entries()) {
	legend_data.push(key);
	var series_values = [];
	for (let i = 0; i < xAxisLabels.length; ++i) {
		var value = keyValueMap.get(xAxisLabels[i]);
		series_values.push(value ? parseInt(value) : null);
	}
	var series_data_item = {
		name: key,
		type: 'line',
		data: series_values
	};
	series_data.push(series_data_item);
}

// Configure the chart
var chart_data = {
	title: { text: 'Appending a log message' },
	yAxis: {
		name: 'Average elapsed time (ns)',
		nameLocation: 'center'
	},
	legend: { 
		orient: 'vertical',
		left: 100,
		top: 'center',
		data: legend_data
	 },
	xAxis: {
		axisTick: { alignWithLabel: true },
		axisLabel: { rotate: 30 },
		name: 'Log message content',
		nameLocation: 'center',
		data: xAxisLabels
	},
	series: series_data
};

// Display the chart
myChart.setOption(chart_data);
