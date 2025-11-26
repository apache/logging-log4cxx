var chart_data = {
	"title": { "text": "Appending a log message" },
	"legend": {
		"orient": "vertical",
		"left": 100,
		"top": "center",
		"data": [ "MessageBuffer", "FMT", "FMT and AsyncBuffer", "operator<< and AsyncBuffer" ]
	},
	"xAxis": {
		axisTick: {
        alignWithLabel: true
      },
      axisLabel: {
        rotate: 30
      },
		name : 'Log message content',
		nameLocation : 'center',
		data : [ "5 char string", "49 char string", "int value", "int+float", "int+10float" ]
	},
	"yAxis": {
		name : 'Average elapsed time (ns)',
		nameLocation : 'center'
		},
	"series": [
		{ "type": "line", "name": "MessageBuffer",              "data": [ 334, 370, 509, 911, 4579 ] },
		{ "type": "line", "name": "FMT",                        "data": [ null, 346, 376, 508, 1671 ] },
		{ "type": "line", "name": "FMT and AsyncBuffer",        "data": [ null, null, null, null, 784 ] },
		{ "type": "line", "name": "operator<< and AsyncBuffer", "data": [ null, null, null, null, 1211 ] }
	]
};

var containerDOM = document.getElementById('appending_a_log_message_plot');
if (containerDOM) {
	var myChart = echarts.init(containerDOM, null, { renderer: 'canvas' });
	myChart.setOption(chart_data);
}
