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

#include <log4cxx/appender.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/rolling/rollingfileappender.h>

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
class LOG4CXX_EXPORT DailyRollingFileAppender : public Appender, log4cxx::helpers::ObjectImpl {
  DECLARE_LOG4CXX_OBJECT(DailyRollingFileAppender)
  BEGIN_LOG4CXX_CAST_MAP()
          LOG4CXX_CAST_ENTRY(DailyRollingFileAppender)
          LOG4CXX_CAST_ENTRY(Appender)
          LOG4CXX_CAST_ENTRY(spi::OptionHandler)
  END_LOG4CXX_CAST_MAP()

  /**
     The date pattern used to initiate rollover.
  */
  LogString datePattern;

  /**
   *  Nested new rolling file appender.
   */
  log4cxx::rolling::RollingFileAppenderPtr rfa;

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

  void addRef() const;
  void releaseRef() const;

  /**
     The <b>DatePattern</b> takes a string in the same format as
     expected by {@link java.text.SimpleDateFormat}. This options determines the
     rollover schedule.
   */
  void setDatePattern(const LogString& pattern);

  /** Returns the value of the <b>DatePattern</b> option. */
  LogString getDatePattern();

  /**
   * Prepares DailyRollingFileAppender for use.
   */
  void activateOptions(log4cxx::helpers::Pool&);

  /**
   * Add a filter to the end of the filter list.
   *
   * 
   */
  void addFilter(const log4cxx::spi::FilterPtr& newFilter);

  /**
   * Returns the head Filter. The Filters are organized in a linked list and
   * so all Filters on this Appender are available through the result.
   *
   * @return the head Filter or null, if no Filters are present
   *
   * 
   */
  log4cxx::spi::FilterPtr getFilter() const;

  /**
   * Clear the list of filters by removing all the filters in it.
   *
   * 
   */
  void clearFilters();

  /**
   * Release any resources allocated within the appender such as file handles,
   * network connections, etc.
   *
   * <p>
   * It is a programming error to append to a closed appender.
   * </p>
   *
   * 
   */
  void close();

  /**
   * Is this appender closed?
   *
   * 
   */
  bool isClosed() const;

  /**
   * Is this appender in working order?
   *
   * 
   */
  bool isActive() const;

  /**
   * Log in <code>Appender</code> specific way. When appropriate, Loggers will
   * call the <code>doAppend</code> method of appender implementations in
   * order to log.
   */
  void doAppend(const log4cxx::spi::LoggingEventPtr& event, log4cxx::helpers::Pool&);

  /**
   * Get the name of this appender. The name uniquely identifies the appender.
   */
  LogString getName() const;

  /**
   * Set the {@link Layout} for this appender.
   *
   * 
   */
  void setLayout(const LayoutPtr& layout);

  /**
   * Returns this appenders layout.
   *
   * 
   */
  LayoutPtr getLayout() const;

  /**
   * Set the name of this appender. The name is used by other components to
   * identify this appender.
   *
   * 
   */
  void setName(const LogString& name);


  /**
     The <b>File</b> property takes a string value which should be the
     name of the file to append to.

     <p><font color="#DD0044"><b>Note that the special values
     "System.out" or "System.err" are no longer honored.</b></font>

     <p>Note: Actual opening of the file is made when {@link
     #activateOptions} is called, not when the options are set.  */
  void setFile(const LogString& file);

  /**
      Returns the value of the <b>Append</b> option.
   */
  bool getAppend() const;

  /** Returns the value of the <b>File</b> option. */
  LogString getFile() const;

  /**
     Get the value of the <b>BufferedIO</b> option.

     <p>BufferedIO will significatnly increase performance on heavily
     loaded systems.

  */
  bool getBufferedIO() const;

  /**
     Get the size of the IO buffer.
  */
  int getBufferSize() const;

  /**
     The <b>Append</b> option takes a boolean value. It is set to
     <code>true</code> by default. If true, then <code>File</code>
     will be opened in append mode by {@link #setFile setFile} (see
     above). Otherwise, {@link #setFile setFile} will open
     <code>File</code> in truncate mode.

     <p>Note: Actual opening of the file is made when {@link
     #activateOptions} is called, not when the options are set.
   */
  void setAppend(bool flag);

  /**
     The <b>BufferedIO</b> option takes a boolean value. It is set to
     <code>false</code> by default. If true, then <code>File</code>
     will be opened and the resulting {@link java.io.Writer} wrapped
     around a {@link java.io.BufferedWriter}.

     BufferedIO will significatnly increase performance on heavily
     loaded systems.

  */
  void setBufferedIO(bool bufferedIO);

  /**
     Set the size of the IO buffer.
  */
  void setBufferSize(int bufferSize);

  void setOption(const LogString&, const LogString&);

  /**
   Set the {@link spi::ErrorHandler ErrorHandler} for this appender.
  */
  void setErrorHandler(const spi::ErrorHandlerPtr& errorHandler);

  /**
   Returns the {@link spi::ErrorHandler ErrorHandler} for this appender.
 */
  const spi::ErrorHandlerPtr& getErrorHandler() const;

  /**
   Configurators call this method to determine if the appender
   requires a layout. If this method returns <code>true</code>,
   meaning that layout is required, then the configurator will
   configure an layout using the configuration information at its
   disposal.  If this method returns <code>false</code>, meaning that
   a layout is not required, then layout configuration will be
   skipped even if there is available layout configuration
   information at the disposal of the configurator..

   <p>In the rather exceptional case, where the appender
   implementation admits a layout but can also work without it, then
   the appender should return <code>true</code>.
  */
  bool requiresLayout() const;


};

LOG4CXX_PTR_DEF(DailyRollingFileAppender)

}

#endif
