/*
 * Copyright 2003-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/logger.h>
#include <apr.h>
#include <apr_time.h>
#include <iostream>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/stream.h>
#include <log4cxx/appender.h>
#include <sstream>
#include "nullappender.h"
#include <log4cxx/consoleappender.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/stream.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::performance;
using namespace log4cxx::xml;



/**
 * Logs in a loop a number of times and measure the elapsed time.
 *
 * @author Ceki G&uuml;lc&uuml;
 */
class Loop {
  static int runLength;
  static LoggerPtr logger;
  typedef long (*loopFunc)(long,LoggerPtr&);
  static loopFunc loop;
public:

  static int main(std::vector<LogString>& args)  {
    LoggerPtr j(Logger::getLogger("org.apache.log4j.joran"));
    j->setAdditivity(false);
    j->setLevel(Level::WARN);
    AppenderPtr a(new ConsoleAppender());
    a->setLayout(new PatternLayout(LOG4CXX_STR("%d %level %c - %m%n")));
    a->setName(LOG4CXX_STR("console"));
    Pool p;
    a->activateOptions(p);
    j->addAppender(a);

    if (args.size() >= 2) {
      init(args);
    } else {
      usage("Wrong number of arguments.");
    }

    //memPrint();
    (*loop)(1000, logger);
    //memPrint();

    long res = (*loop)(runLength, logger);
    double average = (res * 1000.0) / runLength;
    std::cout <<
      "Loop completed in [" << res << "] milliseconds, or [" << average
      << "] microseconds per log.";

    //memPrint();
    return 1;
  }

  static void usage(const char* msg) {
    std::cout << msg << '\n';
    std::cout <<
      "Usage: performance runLength configFile [char wide stream wide-stream bad-stream bad-wide-stream]\n";
    std::cout << "\trunLength (integer) is the length of test loop.";
    std::cout << "\tconfigFile is an XML configuration file";

    exit(1);
  }

  static void memPrint() {
  }

  static void init(std::vector<LogString>& args) {
    std::basic_istringstream<logchar> is(args[0]);
    is >> runLength;
    DOMConfigurator::configure(args[1]);
    if (args.size() == 3) {
      if(args[2] == LOG4CXX_STR("char")) {
        loop = Loop::loopChar;
      } else if (args[2] == LOG4CXX_STR("wide")) {
        loop = Loop::loopWide;
      } else if (args[2] == LOG4CXX_STR("stream")) {
        loop = Loop::loopStream;
      } else if (args[2] == LOG4CXX_STR("wide-stream")) {
        loop = Loop::loopWideStream;
      } else if (args[2] == LOG4CXX_STR("bad-stream")) {
        loop = Loop::loopBadStream;
      } else if (args[2] == LOG4CXX_STR("bad-wide-stream")) {
        loop = Loop::loopBadWideStream;
      } else {
        usage("Unrecognized loop type.");
      }
    }
  }

  static long loopChar(long len, LoggerPtr& logger) {
    const char* msg = "Some fix message of medium length.";
    apr_time_t before = apr_time_now();
    for (int i = 0; i < len; i++) {
      LOG4CXX_DEBUG(logger, msg);
    }
    return (apr_time_now() - before) / 1000;
  }

  static long loopWide(long len, LoggerPtr& logger) {
    const wchar_t* msg = L"Some fix message of medium length.";
    apr_time_t before = apr_time_now();
    for (int i = 0; i < len; i++) {
      LOG4CXX_DEBUG(logger, msg);
    }
    return (apr_time_now() - before) / 1000;
  }

  static long loopStream(long len, LoggerPtr& logger) {
    const char* msg = "Some fix message of medium length.";
    apr_time_t before = apr_time_now();
    logstream ls(logger, Level::DEBUG);
    for (int i = 0; i < len; i++) {
      ls << msg << LOG4CXX_ENDMSG;
    }
    return (apr_time_now() - before) / 1000;
  }

  static long loopWideStream(long len, LoggerPtr& logger) {
    const wchar_t* msg = L"Some fix message of medium length.";
    apr_time_t before = apr_time_now();
    logstream ls(logger, Level::DEBUG);
    for (int i = 0; i < len; i++) {
      ls << msg << LOG4CXX_ENDMSG;
    }
    return (apr_time_now() - before) / 1000;
  }

  static long loopBadStream(long len, LoggerPtr& logger) {
    const char* msg = "Some fix message of medium length.";
    apr_time_t before = apr_time_now();
    for (int i = 0; i < len; i++) {
      logstream ls(logger, Level::DEBUG);
      ls << msg << LOG4CXX_ENDMSG;
    }
    return (apr_time_now() - before) / 1000;
  }

  static long loopBadWideStream(long len, LoggerPtr& logger) {
    const wchar_t* msg = L"Some fix message of medium length.";
    apr_time_t before = apr_time_now();
    for (int i = 0; i < len; i++) {
      logstream ls(logger, Level::DEBUG);
      ls << msg << LOG4CXX_ENDMSG;
    }
    return (apr_time_now() - before) / 1000;
  }


};

LoggerPtr Loop::logger(Logger::getLogger("org.apache.log4j.performance.Loop"));
int Loop::runLength = 0;
Loop::loopFunc Loop::loop = Loop::loopChar;


int main(int argc, const char* const argv[])
{
        apr_app_initialize(&argc, &argv, NULL);
        std::vector<LogString> args(argc - 1);
        for (int i = 1; i < argc; i++) {
           Transcoder::decode(argv[i], args[i - 1]);
        }
        return Loop::main(args);
}
