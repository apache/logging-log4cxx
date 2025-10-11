Log4cxx Performance {#performance}
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

One important question with a logging library is: is it fast enough?
While Log4cxx may not be the fastest logging implementation, it is more than fast
enough for the vast majority of cases.

Using Log4cxx 1.6 you can even use microsecond timestamps
in TRACE level logging messages to quickly get a sense of
where your application's workload is concentrated.
The LOG4CXX_XXXX_ASYNC macros in Log4cxx 1.6
just capture values in a buffer
and by adding the new [asynchronous output setting] to your configuration file,
the values are converted to text in a background thread.
That combination prevents TRACE level logging being the dominate CPU load and
provides the lowest overhead logging in the history of Log4cxx.

While Log4cxx can generate 2,000,000 log messages/second,
skipping a disabled logging request requires only a few nano-seconds,
so application performance is not affected when
logging requests are not removed from the release build.

Benchmark testing shows MessageBuffer (i.e. std::stringstream) filling
consumes the majority of CPU time when the logging request is not disabled.
For the best performance, use the `LOG4CXX_[level]_FMT` series of macros,
as the [{fmt}](https://fmt.dev/latest/index.html) library
they use is significantly faster
(up to twice as fast as `operator<<`).
Note that you must include the headers from {fmt} manually.

These two pieces of logging code are logically equivalent(printing out the same
values), however the one utilizing fmt is close to 2x as fast on some systems.

```{.cpp}
   for( int x = 0; x < howmany; x++ ){
            LOG4CXX_INFO( logger, "Hello logger: msg number " << x);
   }
```

```{.cpp}
   for( int x = 0; x < howmany; x++ ){
       LOG4CXX_INFO_FMT( logger, "Hello logger: msg number {}", x);
   }
```

If you wish to benchmark Log4cxx on your own system, have a look at the tools
under the src/test/cpp/throughput and src/test/cpp/benchmark directories.
The throughput tests may be built by
specifying `BUILD_THROUGHPUT` with CMake when building Log4cxx.
The benckmark tests require Google's [Benchmark](https://github.com/google/benchmark) library
and may be built by specifying `BUILD_BENCHMARK_CHECKS` with CMake when building Log4cxx.

The following table shows some timing tests using Google's benchmarking library.
The "Time" column shows the average elapsed time, i.e real_accumulated_time / iteration_count.
The "CPU" column is also an average, the cpu_accumulated_time / iteration_count.
The "Iterations" column derivation is explained in [Google Benchmark documentation](https://google.github.io/benchmark/user_guide.html#runtime-and-reporting-considerations).

	g++ (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0
	Run on (8 X 2328.61 MHz CPU s)
	CPU Caches:
	  L1 Data 32 KiB (x4)
	  L1 Instruction 32 KiB (x4)
	  L2 Unified 256 KiB (x4)
	  L3 Unified 6144 KiB (x1)
	Load Average: 0.07, 0.03, 0.01

| Benchmark |     Time | CPU | Iterations |
| --------- | -------: | --: | ---------: |
| Testing disabled logging request | 0.472 ns | 0.472 ns | 1000000000 |
| Testing disabled logging request/threads:6 | 0.128 ns | 0.766 ns | 816161856 |
| Appending 5 char string using MessageBuffer, pattern: \%m\%n | 334 ns | 334 ns | 2094794 |
| Appending 5 char string using MessageBuffer, pattern: \%m\%n/threads:6 | 434 ns | 2437 ns | 281586 |
| Appending 49 char string using MessageBuffer, pattern: \%m\%n | 370 ns | 370 ns | 1886606 |
| Appending 49 char string using MessageBuffer, pattern: \%m\%n/threads:6 | 499 ns | 2736 ns | 228720 |
| Appending int value using MessageBuffer, pattern: \%m\%n | 509 ns | 509 ns | 1361391 |
| Appending int value using MessageBuffer, pattern: \%m\%n/threads:6 | 495 ns | 2776 ns | 251646 |
| Appending int+float using MessageBuffer, pattern: \%m\%n | 911 ns | 911 ns | 768870 |
| Appending int+float using MessageBuffer, pattern: \%m\%n/threads:6 | 581 ns | 3370 ns | 203220 |
| Appending int+10float using MessageBuffer, pattern: \%m\%n | 4579 ns | 4567 ns | 151798 |
| Appending int+10float using MessageBuffer, pattern: \%m\%n/threads:6 | 1694 ns | 10092 ns | 65982 |
| Appending int value using MessageBuffer, pattern: [\%d] \%m\%n | 548 ns | 548 ns | 1276999 |
| Appending int value using MessageBuffer, pattern: [\%d] [\%c] [\%p] \%m\%n | 600 ns | 600 ns | 1156877 |
| Appending 49 char string using FMT, pattern: \%m\%n | 346 ns | 346 ns | 2021907 |
| Appending 49 char string using FMT, pattern: \%m\%n/threads:6 | 488 ns | 2672 ns | 257544 |
| Appending int value using FMT, pattern: \%m\%n | 376 ns | 376 ns | 1863727 |
| Appending int value using FMT, pattern: \%m\%n/threads:6 | 486 ns | 2674 ns | 258096 |
| Appending int+float using FMT, pattern: \%m\%n | 508 ns | 508 ns | 1371269 |
| Appending int+float using FMT, pattern: \%m\%n/threads:6 | 537 ns | 3036 ns | 212844 |
| Appending int+10float using FMT, pattern: \%m\%n | 1671 ns | 1671 ns | 417402 |
| Appending int+10float using FMT, pattern: \%m\%n/threads:6 | 1275 ns | 7297 ns | 96222 |
| Async, Sending int+10float using FMT | 2190 ns | 2190 ns | 320109 |
| Async, Sending int+10float using FMT/threads:6 | 1363 ns | 7862 ns | 84306 |
| Async, Sending int+10float using AsyncBuffer, pattern: \%m\%n | 1226 ns | 1226 ns | 571351 |
| Async, Sending int+10float using AsyncBuffer, pattern: \%m\%n/threads:6 | 1398 ns | 7902 ns | 89688 |
| Logging int+float using MessageBuffer, pattern: \%d \%m\%n | 1073 ns | 1073 ns | 656652 |
| Logging int+float using MessageBuffer, pattern: \%d \%m\%n/threads:6 | 1083 ns | 4895 ns | 142776 |
| Logging int+float using MessageBuffer, JSON | 1394 ns | 1394 ns | 507493 |
| Logging int+float using MessageBuffer, JSON/threads:6 | 2110 ns | 6827 ns | 104646 |
| Multiprocess logging int+float using MessageBuffer, pattern: \%d \%m\%n | 3253 ns | 3253 ns | 214839 |

-# The "Appending" benchmarks just format the message (using PatternLayout) then discard the result.
-# The "Async" benchmarks test [AsyncAppender](@ref log4cxx::AsyncAppender) throughput, with logging events discarded in the background thread.
-# The "Logging" benchmarks write to a file using buffered output. Overhead is 2-3 times more when not using buffered output.

The above table shows that the overhead of an enabled logging request
varies greatly with the message content.
A single operations-per-second number is not meaningful.
Most importantly note that [using buffered output](@ref log4cxx::FileAppender::setOption)
reduces overhead more than any other detail.

Note also that logging from multiple threads concurrently
to a common appender generally does not increase throughput
due to lock contention in [doAppend method](@ref log4cxx::AppenderSkeleton::doAppend).
To simplify the work of an appender implementator,
the [doAppend method](@ref log4cxx::AppenderSkeleton::doAppend) currently prevents multiple threads
concurrently entering [the append method](@ref log4cxx::AppenderSkeleton::append),
which is the method required to be implemented by a concrete appender class.

The [AsyncAppender](@ref log4cxx::AsyncAppender) provides the least overhead
when logging concurrently from multiple threads
as it overrides the [doAppend method](@ref log4cxx::AsyncAppender::doAppend)
and uses [std::atomic](https://en.cppreference.com/w/cpp/atomic/atomic.html)
counters and a ring buffer to store logging events.
A single background thread is used to extract the logging events
from the ring bufffer and send them
to the attached appenders.
This moves the overhead of [the layout method](@ref log4cxx::Layout::format)
and the blocking transfer of message data to the operating system
from the calling thread to the background thread.

When logging floating point values from a high priority thread,
and you cannot use a background thread to format and write the log data,
the LOG4CXX_[level]_FMT series of macros impose the least overhead.

[asynchronous output setting]:configuration-files.html#asynch-output
