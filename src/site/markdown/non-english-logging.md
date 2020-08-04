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

# Non-English logging

When logging messages in languages other than English, you may need to
set your locale correctly for messages to be displayed.

For example, here is some Hebrew text which says "People with disabilities":

אנשים עם מוגבלות

If you are to log this information on a system with a locale of `en_US.UTF-8`,
the log message will look something like the following:

```
loggername - ?????????? ???? ??????????????
```

One way to fix this is to call `setlocale` as follows before the function that logs:

```
std::setlocale( LC_ALL, "" );
```

This will then allow the message to be logged appropriately.

See issue [LOG4CXX-483][1] for more information.

[1]:https://issues.apache.org/jira/browse/LOGCXX-483
