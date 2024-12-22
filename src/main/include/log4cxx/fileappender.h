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
#include <log4cxx/helpers/pool.h>

namespace LOG4CXX_NS
{
namespace helpers
{
class Pool;
}

/**
*  FileAppender appends log events to a file.
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
		The default constructor does not do anything.
		*/
		FileAppender();

		/**
		Instantiate a <code>FileAppender</code> and open the file
		designated by <code>filename</code>. The opened filename will
		become the output destination for this appender.

		<p>If the <code>append</code> parameter is true, the file will be
		appended to. Otherwise, the file designated by
		<code>filename</code> will be truncated before being opened.

		<p>If the <code>bufferedIO</code> parameter is <code>true</code>,
		then buffered IO will be used to write to the output file.

		*/
		FileAppender(const LayoutPtr& layout, const LogString& filename, bool append,
			bool bufferedIO, int bufferSize);

		/**
		Instantiate a FileAppender and open the file designated by
		<code>filename</code>. The opened filename will become the output
		destination for this appender.

		<p>If the <code>append</code> parameter is true, the file will be
		appended to. Otherwise, the file designated by
		<code>filename</code> will be truncated before being opened.
		*/
		FileAppender(const LayoutPtr& layout, const LogString& filename, bool append);

		/**
		Instantiate a FileAppender and open the file designated by
		<code>filename</code>. The opened filename will become the output
		destination for this appender.

		<p>The file will be appended to.  */
		FileAppender(const LayoutPtr& layout, const LogString& filename);

		~FileAppender();

		/**
		The <b>File</b> property takes a string value which should be the
		name of the file to append to.

		<p><b>Note that the special values
		"System.out" or "System.err" are no longer honored.</b>

		<p>Note: Actual opening of the file is made when
		#activateOptions is called, not when the options are set.  */
		virtual void setFile(const LogString& file);

		/**
		Returns the value of the <b>Append</b> option.
		*/
		bool getAppend() const;

		/** Returns the value of the <b>File</b> option. */
		LogString getFile() const;

		/**
		\copybrief AppenderSkeleton::activateOptions()

		Sets and <i>opens</i> the file where the log output will
		go. The specified file must be writable.

		If there was already an opened file, then the previous file
		is closed first.
		*/
		void activateOptions(helpers::Pool& p) override;

		/**
		\copybrief AppenderSkeleton::setOption()

		Supported options | Supported values | Default value
		:-------------- | :----------------: | :---------------:
		FileName | {any} | -
		Append | True,False | True
		BufferedIO | True,False | False
		BufferedSeconds | {any} | 5
		ImmediateFlush | True,False | False
		BufferSize | (\ref fileSz1 "1") | 8 KB

		\anchor fileSz1 (1) An integer in the range 0 - 2^63.
		 You can specify the value with the suffixes "KB", "MB" or "GB" so that the integer is
		 interpreted being expressed respectively in kilobytes, megabytes
		 or gigabytes. For example, the value "10KB" will be interpreted as 10240.

		\sa AppenderSkeleton::setOption()
		*/
		void setOption(const LogString& option, const LogString& value) override;

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
		 *   Replaces double backslashes with single backslashes
		 *   for compatibility with paths from earlier XML configurations files.
		 *   @param name file name
		 *   @return corrected file name
		 */
		static LogString stripDuplicateBackslashes(const LogString& name);

	protected:
		void activateOptionsInternal(LOG4CXX_NS::helpers::Pool& p);

		/**
		Sets and <i>opens</i> the file where the log output will
		go. The specified file must be writable.

		<p>If there was already an opened file, then the previous file
		is closed first.

		<p><b>Do not use this method directly. To configure a FileAppender
		or one of its subclasses, set its properties one by one and then
		call activateOptions.</b>

		The mutex must be locked before calling this function.

		@param file The path to the log file.
		@param append If true will append to fileName. Otherwise will
		truncate fileName.
		@param bufferedIO Do we do bufferedIO?
		@param bufferSize How big should the IO buffer be?
		@param p memory pool for operation.
		*/
		void setFileInternal(const LogString& file, bool append,
			bool bufferedIO, size_t bufferSize,
			LOG4CXX_NS::helpers::Pool& p);

		void setFileInternal(const LogString& file);

	private:
		FileAppender(const FileAppender&);
		FileAppender& operator=(const FileAppender&);
	protected:
		FileAppender(std::unique_ptr<FileAppenderPriv> priv);

}; // class FileAppender
LOG4CXX_PTR_DEF(FileAppender);

}  // namespace log4cxx

#endif
