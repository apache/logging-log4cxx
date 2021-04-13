# MapFilter

The MapFilter allows filtering against data elements that are in the Mapped Diagnostic Context (MDC).

| **Parameter Name** 	| **Type**  	| **Description**                                                                                                                                                                                                    	|
|:-------------------	|:----------	|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|
| Operator           	| LogString 	| If the operator is _AND_ then all the key/value pairs must match; any other value is implicitly an _OR_ and a match by any one of the key/value pairs will be considered to be a match. The default value is _OR_. 	|
| AcceptOnMatch      	| LogString 	| Action to take when the filter matches. May be _true_ or _false_. The default value is _false_.                                                                                                                    	|
| MDC key            	| LogString 	| Any name other than _Operator_ or _AcceptOnMatch_ is considered a key to the MDC along with the value to match on. Keys may only be specified once; duplicate keys will replace earlier ones.                      	|

In this configuration, the MapFilter can be used to filter based on system inserted values such as IP address and/or Username. In this example, we assume that the program has inserted appropriate values for *user.ip* and *user.name* into the MDC. In this case, when both the IP address is *127.0.0.1* and the Username is *test*, the entry will not be logged.

1.  &lt;?xml version="1.0" encoding="UTF-8"?&gt;
2.  &lt;log4j:configuration xmlns:log4j="http://logging.apache.org/"&gt;
3.   &lt;appender name="SIMPLE" class="log4cxx.FileAppender"&gt;
4.   &lt;layout class="log4cxx.SimpleLayout"&gt;
5.   &lt;param name="File" value="logs/app.log"/&gt;
6.   &lt;param name="Append" value="true"/&gt;
7.   &lt;/layout&gt;
8.   <br/><br/>
9.   &lt;filter class="log4cxx.MapFilter"&gt;
10.  &lt;param name="user.ip" value="127.0.0.1"/&gt;
11.  &lt;param name="user.name" value="test"/&gt;
12.  &lt;param name="Operator" value="AND"/&gt;
13.  &lt;param name="AcceptOnMatch" value="false"/&gt;
14.  &lt;/filter&gt;
15.  &lt;/appender&gt;
16.  &lt;root&gt;
17.  &lt;priority value="all"/&gt;
18.  &lt;appender-ref ref="SIMPLE"/&gt;
19.  &lt;/root&gt;
20. &lt;/log4j:configuration&gt;

If we wanted to exclude multiple IP addresses from the log, we need to define a separate filter for each one as we don’t support wildcards. Since the default *AcceptOnMatch* value is *false*, we can simplify to a single line per filter. In the configuration below we would skip logs for IP addresses matching 192.168.0.5 - 7.

1.  &lt;?xml version="1.0" encoding="UTF-8"?&gt;
2.  &lt;log4j:configuration xmlns:log4j="http://logging.apache.org/"&gt;
3.   &lt;appender name="SIMPLE" class="log4cxx.FileAppender"&gt;
4.   &lt;layout class="log4cxx.SimpleLayout"&gt;
5.   &lt;param name="File" value="logs/app.log"/&gt;
6.   &lt;param name="Append" value="true"/&gt;
7.   &lt;/layout&gt;
8.   <br/><br/>
9.   &lt;filter class="MapFilter"&gt;&lt;param name="user.ip"
     value="192.168.0.5"/&gt;&lt;/filter&gt;
10.  &lt;filter class="MapFilter"&gt;&lt;param name="user.ip"
     value="192.168.0.6"/&gt;&lt;/filter&gt;
11.  &lt;filter class="MapFilter"&gt;&lt;param name="user.ip"
     value="192.168.0.7"/&gt;&lt;/filter&gt;
12.  &lt;/appender&gt;
13.  &lt;root&gt;
14.  &lt;priority value="all"/&gt;
15.  &lt;appender-ref ref="SIMPLE"/&gt;
16.  &lt;/root&gt;
17. &lt;/log4j:configuration&gt;

In the case where we only want to log entries from a particular set of IP addresses (**not recommended** as this could be a security vulnerability), we need to have a final *DenyAllFilter* to catch the fall through. In this configuration, we would **only** log entries from 192.168.0.251 and 192.168.0.252.

1.  &lt;?xml version="1.0" encoding="UTF-8"?&gt;
2.  &lt;log4j:configuration xmlns:log4j="http://logging.apache.org/"&gt;
3.   &lt;appender name="SIMPLE" class="log4cxx.FileAppender"&gt;
4.   &lt;layout class="log4cxx.SimpleLayout"&gt;
5.   &lt;param name="File" value="logs/app.log"/&gt;
6.   &lt;param name="Append" value="true"/&gt;
7.   &lt;/layout&gt;
8.   <br/><br/>
9.   &lt;filter class="MapFilter"&gt;
10.  &lt;param name="user.ip" value="192.168.0.251"/&gt;
11.  &lt;param name="AcceptOnMatch" value="true"/&gt;
12.  &lt;/filter&gt;
13.  &lt;filter class="MapFilter"&gt;
14.  &lt;param name="user.ip" value="192.168.0.252"/&gt;
15.  &lt;param name="AcceptOnMatch" value="true"/&gt;
16.  &lt;/filter&gt;
17.  &lt;filter class="DenyAllFilter"&gt;
18.  &lt;/appender&gt;
19.  &lt;root&gt;
20.  &lt;priority value="all"/&gt;
21.  &lt;appender-ref ref="SIMPLE"/&gt;
22.  &lt;/root&gt;
23. &lt;/log4j:configuration&gt;
