Fuzzing {#fuzzing}
===
<!--
 Note: License header cannot be first, as doxygen does not generate
 cleanly if it before the '==='
-->
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->
[TOC]

Log4cxx contains fuzz tests implemented using [LibFuzzer](https://llvm.org/docs/LibFuzzer.html#dictionaries).
These tests are located in the `src/fuzzers` directory.

## Google OSS-Fuzz {#oss-fuzz}

[OSS-Fuzz](https://github.com/google/oss-fuzz) is a Google service that continuously runs fuzz tests of critical F/OSS projects on a beefy cluster and reports its findings (bugs, vulnerabilities, etc.) privately to project maintainers.
Log4cxx provides OSS-Fuzz integration with following helpers:

- [Dockerfile](https://github.com/google/oss-fuzz/tree/master/projects/log4cxx/Dockerfile) to create a container image for running tests
- `oss-fuzz-build.sh` to generate fuzz test runner scripts along with all necessary dependencies

## Running tests locally {#running}

1. Clone the OSS-Fuzz repository:
   ~~~~
   git clone --depth 1 https://github.com/google/oss-fuzz google-oss-fuzz && cd $_
   ~~~~
1. Build the container image:
   ~~~~
   python infra/helper.py build_image apache-logging-log4cxx
   ~~~~
1. Run the container image to build the Log4cxx project and generate runner scripts along with dependencies:
   ~~~~
   python infra/helper.py build_fuzzers \
     --sanitizer address --engine libfuzzer --architecture x86_64 \
     apache-logging-log4cxx
   ~~~~
1. List generated runner scripts:
   ~~~~
   ls -al build/out/apache-logging-log4cxx
   ~~~~
1. Check one of the generated runner scripts:
   ~~~~
   python infra/helper.py check_build \
     --sanitizer address --engine libfuzzer --architecture x86_64 \
     apache-logging-log4cxx PatternLayoutFuzzer
   ~~~~
1. Execute one of the generated runner scripts:
   ~~~~
   python infra/helper.py run_fuzzer \
     --sanitizer address --engine libfuzzer --architecture x86_64 \
     apache-logging-log4cxx PatternLayoutFuzzer
   ~~~~

## Viewing fuzzing failures detected by OSS-Fuzz {#view}

The system running fuzzers registered to OSS-Fuzz is called **ClusterFuzz**, which provides [a web interface](https://oss-fuzz.com) for maintainers to monitor the fuzzing results.
Tests outputs and [reproduction](#reproduce) inputs for failed tests are stored in [a Google Cloud Storage bucket](https://console.cloud.google.com/storage/browser/apache-logging-log4cxx-logs.clusterfuzz-external.appspot.com).
Access to both the web interface and the bucket is restricted, and only allowed to [those configured for the project](https://github.com/google/oss-fuzz/blob/master/projects/apache-logging-log4cxx/project.yaml).

## Reproducing fuzzing failures detected by OSS-Fuzz {#reproduce}

Download the associated `.testcase` file from [the Google Cloud Storage bucket](https://console.cloud.google.com/storage/browser/apache-logging-log4cxx-logs.clusterfuzz-external.appspot.com), and run the following command:

~~~~
python infra/helper.py reproduce \
  apache-logging-log4cxx <FUZZ-TARGET-NAME> <TESTCASE-FILE-PATH>
~~~~

Refer to https://google.github.io/oss-fuzz/advanced-topics/reproducing/[the related OSS-Fuzz documentation] for details.
