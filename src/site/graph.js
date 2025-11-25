const data = {
  "context": {
    "date": "2025-11-22T10:20:18-05:00",
    "host_name": "debian",
    "executable": "/home/robert/build-logging-log4cxx-Desktop-Release/src/test/cpp/benchmark/benchmark",
    "num_cpus": 4,
    "mhz_per_cpu": 2808,
    "cpu_scaling_enabled": false,
    "caches": [
      {
        "type": "Data",
        "level": 1,
        "size": 32768,
        "num_sharing": 1
      },
      {
        "type": "Instruction",
        "level": 1,
        "size": 32768,
        "num_sharing": 1
      },
      {
        "type": "Unified",
        "level": 2,
        "size": 262144,
        "num_sharing": 1
      },
      {
        "type": "Unified",
        "level": 3,
        "size": 9437184,
        "num_sharing": 1
      }
    ],
    "load_avg": [0.817383,1.15137,0.766113],
    "library_build_type": "debug"
  },
  "benchmarks": [
    {
      "name": "Testing disabled logging request",
      "family_index": 0,
      "per_family_instance_index": 0,
      "run_name": "Testing disabled logging request",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 1000000000,
      "real_time": 5.1368503500998486e-01,
      "cpu_time": 5.1366347400000001e-01,
      "time_unit": "ns"
    },
    {
      "name": "Testing disabled logging request/threads:2",
      "family_index": 1,
      "per_family_instance_index": 0,
      "run_name": "Testing disabled logging request/threads:2",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 2,
      "iterations": 1331133502,
      "real_time": 2.5778282342153397e-01,
      "cpu_time": 5.1545830374570500e-01,
      "time_unit": "ns"
    },
    {
      "name": "Appending 5 char string using MessageBuffer, pattern: %m%n",
      "family_index": 2,
      "per_family_instance_index": 0,
      "run_name": "Appending 5 char string using MessageBuffer, pattern: %m%n",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 2873996,
      "real_time": 2.4232089293059894e+02,
      "cpu_time": 2.4211321832041520e+02,
      "time_unit": "ns"
    },
    {
      "name": "Appending 5 char string using MessageBuffer, pattern: %m%n/threads:2",
      "family_index": 3,
      "per_family_instance_index": 0,
      "run_name": "Appending 5 char string using MessageBuffer, pattern: %m%n/threads:2",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 2,
      "iterations": 1233886,
      "real_time": 2.8526259233116235e+02,
      "cpu_time": 5.6876204689898441e+02,
      "time_unit": "ns"
    },
    {
      "name": "Appending 49 char string using MessageBuffer, pattern: %m%n",
      "family_index": 4,
      "per_family_instance_index": 0,
      "run_name": "Appending 49 char string using MessageBuffer, pattern: %m%n",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 2567324,
      "real_time": 2.6949126639410900e+02,
      "cpu_time": 2.6926800980320348e+02,
      "time_unit": "ns"
    },
    {
      "name": "Appending 49 char string using MessageBuffer, pattern: %m%n/threads:2",
      "family_index": 5,
      "per_family_instance_index": 0,
      "run_name": "Appending 49 char string using MessageBuffer, pattern: %m%n/threads:2",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 2,
      "iterations": 1120242,
      "real_time": 3.3287094930756729e+02,
      "cpu_time": 6.1510448278139904e+02,
      "time_unit": "ns"
    },
    {
      "name": "Appending int value using MessageBuffer, pattern: %m%n",
      "family_index": 6,
      "per_family_instance_index": 0,
      "run_name": "Appending int value using MessageBuffer, pattern: %m%n",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 1742439,
      "real_time": 4.0594381840651965e+02,
      "cpu_time": 4.0563519468974221e+02,
      "time_unit": "ns"
    },
    {
      "name": "Appending int value using MessageBuffer, pattern: %m%n/threads:2",
      "family_index": 7,
      "per_family_instance_index": 0,
      "run_name": "Appending int value using MessageBuffer, pattern: %m%n/threads:2",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 2,
      "iterations": 1044548,
      "real_time": 3.5002824714622875e+02,
      "cpu_time": 6.9825712557010354e+02,
      "time_unit": "ns"
    },
    {
      "name": "Appending int+float using MessageBuffer, pattern: %m%n",
      "family_index": 8,
      "per_family_instance_index": 0,
      "run_name": "Appending int+float using MessageBuffer, pattern: %m%n",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 1023439,
      "real_time": 6.7125401611294694e+02,
      "cpu_time": 6.7111655702000803e+02,
      "time_unit": "ns"
    },
    {
      "name": "Appending int+float using MessageBuffer, pattern: %m%n/threads:2",
      "family_index": 9,
      "per_family_instance_index": 0,
      "run_name": "Appending int+float using MessageBuffer, pattern: %m%n/threads:2",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 2,
      "iterations": 691026,
      "real_time": 5.1298444196218236e+02,
      "cpu_time": 1.0220948300063965e+03,
      "time_unit": "ns"
    },
    {
      "name": "Appending int+10float using MessageBuffer, pattern: %m%n",
      "family_index": 10,
      "per_family_instance_index": 0,
      "run_name": "Appending int+10float using MessageBuffer, pattern: %m%n",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 131101,
      "real_time": 5.3030657660455963e+03,
      "cpu_time": 5.2971285649995070e+03,
      "time_unit": "ns"
    },
    {
      "name": "Appending int+10float using MessageBuffer, pattern: %m%n/threads:2",
      "family_index": 11,
      "per_family_instance_index": 0,
      "run_name": "Appending int+10float using MessageBuffer, pattern: %m%n/threads:2",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 2,
      "iterations": 193918,
      "real_time": 1.7344036887053321e+03,
      "cpu_time": 3.4637498169329328e+03,
      "time_unit": "ns"
    },
    {
      "name": "Appending int value using MessageBuffer, pattern: [%d] %m%n",
      "family_index": 12,
      "per_family_instance_index": 0,
      "run_name": "Appending int value using MessageBuffer, pattern: [%d] %m%n",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 1603867,
      "real_time": 4.3760817324708853e+02,
      "cpu_time": 4.3756306352085221e+02,
      "time_unit": "ns"
    },
    {
      "name": "Appending int value using MessageBuffer, pattern: [%d] [%c] [%p] %m%n",
      "family_index": 13,
      "per_family_instance_index": 0,
      "run_name": "Appending int value using MessageBuffer, pattern: [%d] [%c] [%p] %m%n",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 1439096,
      "real_time": 4.8595652200906596e+02,
      "cpu_time": 4.8590454980070797e+02,
      "time_unit": "ns"
    },
    {
      "name": "Async, Sending int+10float using operator<< and AsyncBuffer",
      "family_index": 14,
      "per_family_instance_index": 0,
      "run_name": "Async, Sending int+10float using operator<< and AsyncBuffer",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 705145,
      "real_time": 9.8735917717359484e+02,
      "cpu_time": 9.8732187422444861e+02,
      "time_unit": "ns"
    },
    {
      "name": "Async, Sending int+10float using operator<< and AsyncBuffer/threads:2",
      "family_index": 15,
      "per_family_instance_index": 0,
      "run_name": "Async, Sending int+10float using operator<< and AsyncBuffer/threads:2",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 2,
      "iterations": 424000,
      "real_time": 7.6162264151276281e+02,
      "cpu_time": 1.5194786863207555e+03,
      "time_unit": "ns"
    },
    {
      "name": "Logging int+float using MessageBuffer, pattern: %d %m%n",
      "family_index": 16,
      "per_family_instance_index": 0,
      "run_name": "Logging int+float using MessageBuffer, pattern: %d %m%n",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 836285,
      "real_time": 8.1514249568640287e+02,
      "cpu_time": 8.1475318103278187e+02,
      "time_unit": "ns"
    },
    {
      "name": "Logging int+float using MessageBuffer, pattern: %d %m%n/threads:2",
      "family_index": 17,
      "per_family_instance_index": 0,
      "run_name": "Logging int+float using MessageBuffer, pattern: %d %m%n/threads:2",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 2,
      "iterations": 320264,
      "real_time": 1.6090834467678897e+03,
      "cpu_time": 2.2111380080183872e+03,
      "time_unit": "ns"
    },
    {
      "name": "Logging int+float using MessageBuffer, JSON",
      "family_index": 18,
      "per_family_instance_index": 0,
      "run_name": "Logging int+float using MessageBuffer, JSON",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 1,
      "iterations": 568816,
      "real_time": 1.2087415526226423e+03,
      "cpu_time": 1.2075170371438192e+03,
      "time_unit": "ns"
    },
    {
      "name": "Logging int+float using MessageBuffer, JSON/threads:2",
      "family_index": 19,
      "per_family_instance_index": 0,
      "run_name": "Logging int+float using MessageBuffer, JSON/threads:2",
      "run_type": "iteration",
      "repetitions": 1,
      "repetition_index": 0,
      "threads": 2,
      "iterations": 211138,
      "real_time": 2.4913516278319262e+03,
      "cpu_time": 3.1669491706845761e+03,
      "time_unit": "ns"
    }
  ]
}

console.log("do the graph");

var single_thread_data = [];
var single_thread_labels = [];
var multi_thread_data = [];
var multi_thread_labels = [];
var all_data = [];
var all_labels = [];
for(const benchmark of data.benchmarks){
	if(benchmark.threads == 1){
		single_thread_data.push(benchmark.name);
		single_thread_labels.push(benchmark.cpu_time);
	}else{
		multi_thread_data.push(benchmark.name);
		multi_thread_labels.push(benchmark.cpu_time);
	}
	all_labels.push(benchmark.name);
	all_data.push(benchmark.cpu_time);
}

var myChart = echarts.init(document.getElementById('main'));
// Specify the configuration items and data for the chart
var option = {
	title: {
		text: 'All Performance Options'
	},
	tooltip: {},
	legend: { data: ['Single Thread', 'Multi Thread']},
	xAxis: {
		data: all_labels
	},
	yAxis: {},
	series: [
	{
		data: all_data,
		type: 'bar'
	}
	]
};

// Display the chart using the configuration items and data just specified.
myChart.setOption(option);
