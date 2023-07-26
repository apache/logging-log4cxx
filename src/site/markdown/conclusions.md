Conclusions {#conclusions}
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

Apache Log4cxx is a popular logging package written in C++. One of its
distinctive features is the notion of inheritance in loggers. Using a
logger hierarchy it is possible to control which log statements are
output at arbitrary granularity. This helps reduce the volume of logged
output and minimize the cost of logging.

One of the advantages of the Log4cxx API is its manageability. Once the
log statements have been inserted into the code, they can be controlled
with configuration files. They can be selectively enabled or disabled,
and sent to different and multiple output targets in user-chosen
formats. The Log4cxx package is designed so that log statements can
remain in shipped code without incurring a heavy performance cost.
