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

#ifndef _LOG4CXX_FILE_APPENDER_H
#define _LOG4CXX_FILE_APPENDER_H

#include <log4cxx/logger.h>
#include <log4cxx/logstring.h>
#include <log4cxx/writerappender.h>
#include <log4cxx/file.h>

namespace LOG4CXX_NS
{

/**
*  FileAppender appends log events to a file.
*
* The file is opened/created immediately by #activateOptions()
* unless the <code>LazyFileCreation</code> option is set <code>true</code>,
* in which case the file is opened/created when the first spi::LoggingEvent is added.
*
*  Uses a background thread to periodically flush the output buffer
*  when <code>BufferedIO</code> option is set <code>true</code>.
*  Use the <code>BufferedSeconds</code> option to control the frequency,
*  using <code>0</code> to disable the background output buffer flush.
*  Refer to FileAppender::setOption() for more information.
*
*/
class LOG4CXX_EXPORT FileAppender : public WriterAppender
{
	protected:
		struct FileAppenderPriv;

	public:
		DECLARE_LOG4CXX_OBJECT(FileAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(FileAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(WriterAppender)
		END_LOG4CXX_CAST_MAP()

		/**
		An unconfigured Appender.
		*/
		FileAppender();

		/**
		Open \c fileName and prepare to write spi::LoggingEvent
		messages formatted by \c layout.

		The preexisting content of \c fileName will be preserved
		if \c appendToExistingFile is <code>true</code>,
		otherwise, it will be removed when \c fileName is opened.

		If the \c useBufferedOutput parameter is <code>true</code>,
		log messages will be accumulated in a \c bufferByteCount sized buffer
		before being writen to \c fileName.
		*/
		FileAppender
			( const LayoutPtr& layout
			, const LogString& fileName
			, bool             appendToExistingFile = true
			, bool             useBufferedOutput = false
			, int              bufferByteCount = DefaultBufferedByteCount
			);

		~FileAppender();

		/**
		The <b>File</b> property takes a string value which should be the
		name of the file to append to.

		<p><b>Note that the special values
		"System.out" or "System.err" are no longer honored.</b>

		<p>Note: Actual opening of the file is made when
		#activateOptions is called, not when the options are set.  */
		void setFile(const LogString& file);

		/**
		Returns the value of the <b>Append</b> option.
		*/
		bool getAppend() const;

		/** Returns the value of the <b>File</b> option. */
		LogString getFile() const;

		using WriterAppender::activateOptions;
		/**
		\copybrief WriterAppender::activateOptions()

		When <code>LazyFileCreation</code> and <code>Append</code> are both set to <code>true</code>,
		the file is opened/created when the first spi::LoggingEvent is added,
		otherwise #activateOptions will open/create the file.

		When <code>BufferedIO</code> is <code>true</code> and
		<code>BufferedSeconds</code> is greater than zero,
		a background task is started that will periodically flush the buffer.
		*/
		void activateOptions(  ) override;

		/**
		\copybrief AppenderSkeleton::setOption()

		Supported options | Supported values | Default value |
		:-------------- | :----------------: | :---------------: |
		FileName | {any} | - |
		Append | True,False | True |
		BufferedIO | True,False | False |
		BufferedSeconds | {any} | 5 |
		LazyFileCreation | True,False | False |
		ImmediateFlush | True,False | False |
		BufferSize | (\ref fileSz1 "1") | 8 KB |

		\anchor fileSz1 (1) An integer in the range 0 - 2^32.
		 You can specify the value with the suffixes "KB" or "MB" so that the integer is
		 interpreted being expressed respectively in kilobytes or megabytes.
		 For example, the value "10KB" will be interpreted as 10240.

		\sa AppenderSkeleton::setOption()
		*/
		void setOption(const LogString& option, const LogString& value) override;

		/**
		Get the value of the <b>BufferedIO</b> option.

		<p>Using buffered output will significantly reduce logging overhead.

		*/
		bool getBufferedIO() const;

		/**
		Get the size of the IO buffer.
		*/
		int getBufferSize() const;

		/**
		Get the number of seconds between file writes
		when the <code>BufferedIO</code> option is <code>true</code>.
		*/
		int getBufferedSeconds() const;

		/**
		Set file open mode to \c newValue.

		The <b>Append</b> option takes a boolean value. It is set to
		<code>true</code> by default. If true, then <code>File</code>
		will be opened in append mode by #setFile (see
		above). Otherwise, setFile will open
		<code>File</code> in truncate mode.

		<p>Note: The file is opened when
		#activateOptions is called, not when the options are set.
		*/
		void setAppend(bool newValue);

		/**
		Set buffered output behavior to \c newValue.

		By default buffered output is disabled and
		this appender writes each log message directly to the file.
		When buffered output is enabled,
		log messages are stored into a memory buffer
		and written to the file periodically or when the buffer is full.

		Using buffered output will significantly reduce logging overhead.

		Note: Behavior change occurs when
		#activateOptions is called, not when the options are set.
		*/
		void setBufferedIO(bool newValue);

		/**
		Use \c newValue as the size of the output buffer.
		*/
		void setBufferSize(int newValue);

		/**
		Flush the output buffer every \c newValue seconds.
		The default period is 5 seconds.

		Note: #activateOptions must be called after an option is changed
		to activate the new frequency.
		*/
		void setBufferedSeconds(int newValue);

		/**
		Create the file when the first message is written (rather than in #activateOptions)
		if \c newValue is true, so that no empty file is created when nothing is logged.
		The default is false.

		Note: Behavior change occurs when
		#activateOptions is called, not when the options are set.
		*/
		void setLazyFileCreation(bool newValue);

		/**
		Get the value of the <b>LazyFileCreation</b> option.
		*/
		bool getLazyFileCreation() const;

		/**
		 *   Replaces double backslashes with single backslashes
		 *   for compatibility with paths from earlier XML configurations files.
		 *   @param name file name
		 *   @return corrected file name
		 */
		static LogString stripDuplicateBackslashes(const LogString& name);

		static const int DefaultBufferedByteCount = 8 * 1024;
	private:
		FileAppender(const FileAppender&);
		FileAppender& operator=(const FileAppender&);
	protected:
		FileAppender(std::unique_ptr<FileAppenderPriv> priv);

}; // class FileAppender
LOG4CXX_PTR_DEF(FileAppender);

}  // namespace log4cxx

#endif
