Filtering Log Messages {#filters}
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

# Filtering Messages {#filtering}

When dealing with large amounts of logging information, it can be useful
to filter on messages that we are interested in.  This filtering only
takes places after determining that the level of the current logger would
log the message in the first place.  When defining filters, note that
they can only be defined on a per-appender basis, they do not globally
affect anything.

The filtering system is similar in concept to Linux iptables rules, in
that there is a chain of filters that can accept a log message, deny the
log message, or pass the message on to the next filter. Accepting a log
message means that the message will be logged immediately without
consulting other filters.  Denying has the opposite affect, immediately
dropping the log message and not consulting any other filters.

See the documentation for [Filter](@ref log4cxx.spi.Filter) for some more
information, or view a [configuration sample](@ref configuration-samples).

The following filters are available:
* [AndFilter](@ref log4cxx.filter.AndFilter) - Takes in a list of filters that must all match
* [DenyAllFilter](@ref log4cxx.filter.DenyAllFilter) - Drops all log messages that reach it
* [LevelMatchFilter](@ref log4cxx.filter.LevelMatchFilter) - Filter log messages based off of their level
* [LevelRangeFilter](@ref log4cxx.filter.LevelRangeFilter) - Filter log messages based off of their level in a given range
* [LocationInfoFilter](@ref log4cxx.filter.LocationInfoFilter) - Filter log messages based off of their location(line number and/or method name)
* [LoggerMatchFilter](@ref log4cxx.filter.LoggerMatchFilter) - Accept or deny depending on the logger that generated the message
* [MapFilter](@ref log4cxx.filter.MapFilter) - Based off of the log messages MDC, accept or deny the message
* [StringMatchFilter](@ref log4cxx.filter.StringMatchFilter) - If the given substring is found in the message, accept or deny

The following pages have information on specific filters:

* @subpage map-filter
* @subpage location-info-filter
