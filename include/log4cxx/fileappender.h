/***************************************************************************
                          fileappender.h  -  description
                             -------------------
    begin                : sam avr 26 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_FILE_APPENDER_H
#define _LOG4CXX_FILE_APPENDER_H

#include <log4cxx/config.h>
#include <log4cxx/helpers/tchar.h>
#include <log4cxx/writerappender.h>
#include <fstream>

namespace log4cxx
{
	class FileAppender;
	typedef helpers::ObjectPtrT<FileAppender> FileAppenderPtr;

	/**
	*  FileAppender appends log events to a file.
	*
	*  <p>Support for <code>java.io.Writer</code> and console appending
	*  has been deprecated and then removed. See the replacement
	*  solutions: WriterAppender and ConsoleAppender.
	*/
 	class FileAppender : public WriterAppender
	{
	protected:
		/** Append to or truncate the file? The default value for this
		variable is <code>true</code>, meaning that by default a
		code>FileAppender</code> will append to an existing file and
		not truncate it.
		<p>This option is meaningful only if the FileAppender opens the
		file.
		*/
		bool fileAppend;

		/**
		The name of the log file. */
		tstring fileName; 

		/**
		Do we do bufferedIO? */
		bool bufferedIO;

		/**
		How big should the IO buffer be? Default is 8K. */
		int bufferSize;

#ifdef UNICODE
		std::wofstream ofs;
#else
		std::ofstream ofs;
#endif

	public:
		DECLARE_LOG4CXX_OBJECT(FileAppender)
		BEGIN_LOG4CXX_INTERFACE_MAP()
			LOG4CXX_INTERFACE_ENTRY(FileAppender)
			LOG4CXX_INTERFACE_ENTRY_CHAIN(WriterAppender)
		END_LOG4CXX_INTERFACE_MAP()

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
		FileAppender(LayoutPtr layout, const tstring& filename, bool append, 
			bool bufferedIO, int bufferSize);

		/**
		Instantiate a FileAppender and open the file designated by
		<code>filename</code>. The opened filename will become the output
		destination for this appender.

		<p>If the <code>append</code> parameter is true, the file will be
		appended to. Otherwise, the file designated by
		<code>filename</code> will be truncated before being opened.
		*/
		FileAppender(LayoutPtr layout, const tstring& filename, bool append);

		/**
		Instantiate a FileAppender and open the file designated by
		<code>filename</code>. The opened filename will become the output
		destination for this appender.

		<p>The file will be appended to.  */
		FileAppender(LayoutPtr layout, const tstring& filename);

		~FileAppender();

		/**
		The <b>File</b> property takes a string value which should be the
		name of the file to append to.

		<p><font color="#DD0044"><b>Note that the special values
		"System.out" or "System.err" are no longer honored.</b></font>

		<p>Note: Actual opening of the file is made when 
		#activateOptions is called, not when the options are set.  */
		void setFile(const tstring& file);
			
		/**
		Returns the value of the <b>Append</b> option.
		*/
		inline bool getAppend() { return fileAppend; }

		/** Returns the value of the <b>File</b> option. */
		inline const tstring& getFile() { return fileName; }

        /**
        <p>Sets and <i>opens</i> the file where the log output will
        go. The specified file must be writable.

        <p>If there was already an opened file, then the previous file
        is closed first.*/
        
		void activateOptions();
		void setOption(const tstring& option,
			const tstring& value);

	protected:
        /**
        Closes the previously opened file.
        */
        virtual void closeWriter();

    public:
        /**
        Get the value of the <b>BufferedIO</b> option.

        <p>BufferedIO will significatnly increase performance on heavily
        loaded systems.

        */
        inline bool getBufferedIO() const { return bufferedIO; }

        /**
        Get the size of the IO buffer.
        */
       inline  int getBufferSize() const { return bufferSize; }

        /**
        The <b>Append</b> option takes a boolean value. It is set to
        <code>true</code> by default. If true, then <code>File</code>
        will be opened in append mode by #setFile (see
        above). Otherwise, setFile will open
        <code>File</code> in truncate mode.

        <p>Note: Actual opening of the file is made when 
        #activateOptions is called, not when the options are set.
        */
        inline void setAppend(bool fileAppend) 
			{ this->fileAppend = fileAppend; }
        /**
        The <b>BufferedIO</b> option takes a boolean value. It is set to
        <code>false</code> by default. If true, then <code>File</code>
        will be opened in buffered mode.

        BufferedIO will significantly increase performance on heavily
        loaded systems.

        */
        void setBufferedIO(bool bufferedIO);

        /**
        Set the size of the IO buffer.
        */
        void setBufferSize(int bufferSize) { this->bufferSize = bufferSize; }
			
	}; // class FileAppender
}; // namespace log4cxx

#endif
