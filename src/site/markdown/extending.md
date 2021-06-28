Extending Log4cxx {#extending-log4cxx}
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

Sometimes, you may want to extend Log4cxx, for example by creating
a new appender to write out data in a new format.  The following
guide shows how you can extend Log4cxx in order to add a new appender.

The full sample application can be found in the src/examples/cpp
directory.

The first thing for our example is to create a class that extends
log4cxx.AppenderSkeleton so that we don't need to implement all of
the virtual methods that are defined in log4cxx.Appender:

~~~{.cpp}
namespace log4cxx {

class NullWriterAppender : public log4cxx::AppenderSkeleton {
};

}
~~~

Next, we need to add in a few macros in order to properly register
our new appender with Log4cxx:

~~~{.cpp}
namespace log4cxx {

class NullWriterAppender : public log4cxx::AppenderSkeleton {
public:
	DECLARE_LOG4CXX_OBJECT(NullWriterAppender)
	BEGIN_LOG4CXX_CAST_MAP()
	LOG4CXX_CAST_ENTRY(NullWriterAppender)
	LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
	END_LOG4CXX_CAST_MAP()

};

IMPLEMENT_LOG4CXX_OBJECT(NullWriterAppender)

}
~~~

These macros tell Log4cxx what the name of our class is, as well as giving
Log4cxx a way of instansiating our class.  Without these macros, the custom
class will not work.

Now, let's add some basic functionality to our class.  As the name of
our class implies, we are going to do nothing with our appender here, as
this is just an example.  To that end, we need to implement the following:
1. Default constructor
2. `close` method
3. `requiresLayout` method
4. `append` method, which does the actual writing of the log event
5. `activateOptions`, which causes the class to reconfigure itself
6. `setOption`, which gets called whenever we get an option in a config file

These are basically stub methods, with a few comments on their use:

~~~{.cpp}
	NullWriterAppender(){}

	virtual void close(){}

	virtual bool requiresLayout() const {
		return false;
	}

	virtual void append(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p){
		// This gets called whenever there is a valid event for our appender.
	}

	virtual void activateOptions(log4cxx::helpers::Pool& /* pool */) {
		// Given all of our options, do something useful(e.g. open a file)
	}

	virtual void setOption(const LogString& option, const LogString& value){
		if (helpers::StringHelper::equalsIgnoreCase(option,
			   LOG4CXX_STR("SOMEVALUE"), LOG4CXX_STR("somevalue"))){
			// Do something with the 'value' here.
		}
	}
~~~

At this point, we now have a fully functioning(if useless) custom appender.  We can now
refer to this appender in our configuration file like so:

~~~{.xml}
<?xml version="1.0" encoding="UTF-8" ?>
<log4j:configuration xmlns:log4j="http://jakarta.apache.org/log4j/">
  <appender name="ConsoleAppender" class="org.apache.log4j.ConsoleAppender">
    <param name="Target" value="System.out"/>
    <layout class="org.apache.log4j.PatternLayout">
      <param name="ConversionPattern" value="[%d{yyyy-MM-dd HH:mm:ss}] %c %-5p - %m%n"/>
    </layout>
  </appender>

  <appender name="NullAppender" class="NullWriterAppender">
    <param name="SomeValue" value="Nothing"/>
  </appender>

  <root>
     <priority value="info" />
     <appender-ref ref="ConsoleAppender"/>
  </root>

  <logger name="NullLogger" additivity="false">
     <appender-ref ref="NullAppender"/>
  </logger>
</log4j:configuration>
~~~

When Log4cxx is configured, any messages that go to the `NullLogger` will
then be forwarded on to the `NullWriterAppender`.

This same technique can be used to add new classes of many different kinds
to Log4cxx, including(but not limited to):
* [Appenders](@ref log4cxx.Appender)
* [Layouts](@ref log4cxx.Layout)
* [Filters](@ref log4cxx.spi.Filter)
