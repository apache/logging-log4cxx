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
#ifndef _LOG4CXX_ROLLING_FILE_APPENDER_H
#define _LOG4CXX_ROLLING_FILE_APPENDER_H

#if defined(_MSC_VER)
#pragma warning ( push )
#pragma warning ( disable: 4231 4251 4275 4786 )
#endif

#include <log4cxx/rolling/rollingfileappender.h>

namespace log4cxx
{

  /** RollingFileAppender extends FileAppender to backup the log files when they reach a certain size. */
  class LOG4CXX_EXPORT RollingFileAppender : public log4cxx::helpers::ObjectImpl, public Appender
  {
  private:
    /** The default maximum file size is 10MB. */
    long maxFileSize;

    /** There is one backup file by default. */
    int maxBackupIndex;

    log4cxx::rolling::RollingFileAppenderPtr rfa;

  public:
    //
    //   Use custom class to use non-default name to avoid
    //       conflict with log4cxx::rolling::RollingFileAppender
    DECLARE_LOG4CXX_OBJECT_WITH_CUSTOM_CLASS( RollingFileAppender, ClassRollingFileAppender )
    BEGIN_LOG4CXX_CAST_MAP()
         LOG4CXX_CAST_ENTRY( RollingFileAppender )
         LOG4CXX_CAST_ENTRY( Appender )
         LOG4CXX_CAST_ENTRY( spi::OptionHandler)
    END_LOG4CXX_CAST_MAP()
    /** The default constructor simply calls its {@link FileAppender#FileAppender parents constructor}. */
    RollingFileAppender();
   void addRef() const;
   void releaseRef() const;

    /**
                    Instantiate a RollingFileAppender and open the file designated by
     <code>filename</code>. The opened filename will become the ouput destination for this appender.

    <p>If the <code>append</code> parameter is true, the file will be appended to. Otherwise, the file desginated by
     <code>filename</code> will be truncated before being opened.
    */
    RollingFileAppender( const LayoutPtr & layout, const LogString & fileName, bool append );

    /**
                    Instantiate a FileAppender and open the file designated by
     <code>filename</code>. The opened filename will become the output destination for this appender.
     <p>The file will be appended to.
    */
    RollingFileAppender( const LayoutPtr & layout, const LogString & fileName );

    virtual ~RollingFileAppender();

    /** Returns the value of the <b>MaxBackupIndex</b> option. */
    int getMaxBackupIndex() const;

    /** Get the maximum size that the output file is allowed to reach before being rolled over to backup files. */
    long getMaximumFileSize() const;

    /**
                    Implements the usual roll over behaviour.

    <p>If <code>MaxBackupIndex</code> is positive, then files {<code>File.1</code>, ..., <code>File.MaxBackupIndex -1</code>}
     are renamed to {<code>File.2</code>, ..., <code>File.MaxBackupIndex</code>}. Moreover, <code>File</code> is
     renamed <code>File.1</code> and closed. A new <code>File</code> is created to receive further log output.

    <p>If <code>MaxBackupIndex</code> is equal to zero, then the <code>File</code> is truncated with no backup files created.
    */
    // synchronization not necessary since doAppend is alreasy synched
    void rollOver();

    /**
                    Set the maximum number of backup files to keep around.

    <p>The <b>MaxBackupIndex</b> option determines how many backup
     files are kept before the oldest is erased. This option takes
     a positive integer value. If set to zero, then there will be no
     backup files and the log file will be truncated when it reaches <code>MaxFileSize</code>.
    */
    void setMaxBackupIndex( int maxBackupIndex );

    /**
                    Set the maximum size that the output file is allowed to reach before being rolled over to backup files.

    <p>In configuration files, the <b>MaxFileSize</b> option takes an
     long integer in the range 0 - 2^63. You can specify the value with the suffixes "KB", "MB" or "GB" so that the integer is
     interpreted being expressed respectively in kilobytes, megabytes
     or gigabytes. For example, the value "10KB" will be interpreted as 10240.
    */
    void setMaxFileSize( const LogString & value );

    void setMaximumFileSize( int value );


    virtual void setOption( const LogString & option, const LogString & value );

    /** Prepares RollingFileAppender for use. */
    void activateOptions( log4cxx::helpers::Pool & pool );


    /**
     Add a filter to the end of the filter list.

    
    */
    void addFilter( const log4cxx::spi::FilterPtr & newFilter );

    /**
     Returns the head Filter. The Filters are organized in a linked list and
     so all Filters on this Appender are available through the result.

     @return the head Filter or null, if no Filters are present

    
    */
    log4cxx::spi::FilterPtr getFilter() const;

    /**
     Clear the list of filters by removing all the filters in it.

    
    */
    void clearFilters();

    /**
     Release any resources allocated within the appender such as file handles, network connections, etc.

    <p> It is a programming error to append to a closed appender. </p>

    
    */
    void close();

    /**
     Is this appender closed?

    
    */
    bool isClosed() const;

    /**
     Is this appender in working order?

    
    */
    bool isActive() const;

    /**
     Log in <code>Appender</code> specific way. When appropriate, Loggers will
     call the <code>doAppend</code> method of appender implementations in order to log.
    */
    void doAppend( const log4cxx::spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p );

    /** Get the name of this appender. The name uniquely identifies the appender. */
    LogString getName() const;

    /**
     Set the {@link Layout} for this appender.

    
    */
    void setLayout( const LayoutPtr & layout );

    /**
     Returns this appenders layout.

    
    */
    LayoutPtr getLayout() const;

    /**
     Set the name of this appender. The name is used by other components to identify this appender.

    
    */
    void setName( const LogString & name );


    /**
       The <b>File</b> property takes a string value which should be the name of the file to append to.

    <p><font color="#DD0044"><b>Note that the special values "System.out" or "System.err" are no longer honored.</b></font>

    <p>Note: Actual opening of the file is made when {@link #activateOptions} is called, not when the options are set.
    */
    void setFile( const LogString & file );

    /** Returns the value of the <b>Append</b> option. */
    bool getAppend() const;

      /** Returns the value of the <b>File</b> option. */
      LogString getFile() const;

      /**
         Get the value of the <b>BufferedIO</b> option.

      <p>BufferedIO will significatnly increase performance on heavily loaded systems.

       */
      bool getBufferedIO() const;

      /** Get the size of the IO buffer. */
      int getBufferSize() const;

        /**
           The <b>Append</b> option takes a boolean value. It is set to
         <code>true</code> by default. If true, then <code>File</code>
         will be opened in append mode by {@link #setFile setFile} (see above). Otherwise, {@link #setFile setFile} will open
         <code>File</code> in truncate mode.

        <p>Note: Actual opening of the file is made when {@link #activateOptions} is called, not when the options are set.
         */
        void setAppend( bool flag );

        /**
           The <b>BufferedIO</b> option takes a boolean value. It is set to
         <code>false</code> by default. If true, then <code>File</code>
         will be opened and the resulting {@link java.io.Writer} wrapped around a {@link java.io.BufferedWriter}.

        BufferedIO will significatnly increase performance on heavily loaded systems.

         */
        void setBufferedIO( bool bufferedIO );

        /** Set the size of the IO buffer. */
        void setBufferSize( int bufferSize );

        bool requiresLayout() const;

      }; // class RollingFileAppender
      LOG4CXX_PTR_DEF(RollingFileAppender)

    } // namespace log4cxx


#if defined(_MSC_VER)
#pragma warning ( pop )
#endif

#endif //_LOG4CXX_ROLLING_FILE_APPENDER_H
