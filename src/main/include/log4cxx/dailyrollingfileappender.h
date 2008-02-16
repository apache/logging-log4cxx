/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LOG4CXX_DAILYROLLINGFILEAPPENDER_H
#define _LOG4CXX_DAILYROLLINGFILEAPPENDER_H

#if defined(_MSC_VER)
#pragma warning ( push )
#pragma warning ( disable: 4231 4251 4275 4786 )
#endif


#include <log4cxx/appender.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/rolling/rollingfileappenderskeleton.h>

namespace log4cxx {
  namespace helpers {
    class Pool;
  }

  namespace spi {
    class ErrorHandler;
    typedef log4cxx::helpers::ObjectPtrT<ErrorHandler> ErrorHandlerPtr;
  }


/**
  * org.apache.log4j.DailyRollingFileAppender emulates earlier implementations
  * by delegating to general purpose org.apache.log4j.rollling.RollingFileAppender
  * introduced in log4j 1.3.  This class is provided for compatibility with
  *  existing code and should not be used except when compatibility with version
  * of log4j prior to 1.3 is a concern.
  *
  *  
  * @deprecated Replaced by {@link org.apache.log4j.rolling.RollingFileAppender}
*/
  class LOG4CXX_EXPORT DailyRollingFileAppender : public log4cxx::rolling::RollingFileAppenderSkeleton {
  DECLARE_LOG4CXX_OBJECT(DailyRollingFileAppender)
  BEGIN_LOG4CXX_CAST_MAP()
          LOG4CXX_CAST_ENTRY(DailyRollingFileAppender)
          LOG4CXX_CAST_ENTRY_CHAIN(FileAppender)
  END_LOG4CXX_CAST_MAP()

  /**
     The date pattern used to initiate rollover.
  */
  LogString datePattern;


public:
  /**
     The default constructor simply calls its {@link
     FileAppender#FileAppender parents constructor}.  */
  DailyRollingFileAppender();

  /**
    Instantiate a DailyRollingFileAppender and open the file designated by
    <code>filename</code>. The opened filename will become the ouput
    destination for this appender.

  */
  DailyRollingFileAppender(
    const LayoutPtr& layout,
    const LogString& filename,
    const LogString& datePattern);


  /**
     The <b>DatePattern</b> takes a string in the same format as
     expected by {@link java.text.SimpleDateFormat}. This options determines the
     rollover schedule.
   */
  void setDatePattern(const LogString& pattern);

  /** Returns the value of the <b>DatePattern</b> option. */
  LogString getDatePattern();

  void setOption(const LogString& option,
   const LogString& value);

  /**
   * Prepares DailyRollingFileAppender for use.
   */
  void activateOptions(log4cxx::helpers::Pool&);

};

LOG4CXX_PTR_DEF(DailyRollingFileAppender)

}

#if defined(_MSC_VER)
#pragma warning ( pop )
#endif


#endif
