/***************************************************************************
                          fileappender.cpp  -  description
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

#include <log4cxx/fileappender.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

FileAppender::FileAppender()
: fileAppend(true), bufferedIO(false), bufferSize(8*1024)
{
}

FileAppender::FileAppender(LayoutPtr layout, const tstring& fileName,
	bool append, bool bufferedIO, int bufferSize)
: fileName(fileName), fileAppend(append), bufferedIO(bufferedIO), bufferSize(bufferSize)
{
	this->layout = layout;
	activateOptions();
}

FileAppender::FileAppender(LayoutPtr layout, const tstring& fileName,
	bool append)
: fileName(fileName), fileAppend(append), bufferedIO(false), bufferSize(8*1024)
{
	this->layout = layout;
	activateOptions();
}

FileAppender::FileAppender(LayoutPtr layout, const tstring& fileName)
: fileName(fileName), fileAppend(true), bufferedIO(false), bufferSize(8*1024)
{
	this->layout = layout;
	activateOptions();
}

FileAppender::~FileAppender()
{
	finalize();
}

void FileAppender::setFile(const tstring& file)
{
	// Trim spaces from both ends. The users probably does not want
	// trailing spaces in file names.
	fileName = StringHelper::trim(file);
}

void FileAppender::closeWriter()
{
	ofs.close();
	os = 0;
}

void FileAppender::setBufferedIO(bool bufferedIO)
{
	this->bufferedIO = bufferedIO;
	if(bufferedIO)
	{
		immediateFlush = false;
	}
}

void FileAppender::setOption(const std::string& option,
	const std::string& value)
{
	if (StringHelper::equalsIgnoreCase(option, _T("file")))
	{
		fileName = value;
	}
	else if (StringHelper::equalsIgnoreCase(option, _T("append")))
	{
		fileAppend = OptionConverter::toBoolean(value, true);
	}
	else if (StringHelper::equalsIgnoreCase(option, _T("bufferedio")))
	{
		bufferedIO = OptionConverter::toBoolean(value, true);
	}
	else if (StringHelper::equalsIgnoreCase(option, _T("buffersize")))
	{
		bufferSize = OptionConverter::toFileSize(value, 8*1024);
	}
	else
	{
		WriterAppender::setOption(name, value);
	}
}

void FileAppender::activateOptions()
{
	if (!fileName.empty())
	{
		LOGLOG_DEBUG(_T("FileAppender::activateOptions called : ")
			<< fileName << _T(", ") << fileAppend);
		// It does not make sense to have immediate flush and bufferedIO.
		if(bufferedIO)
		{
			setImmediateFlush(false);
		}

		if(ofs.is_open())
		{
			reset();
		}

	/*	if (bufferedIO && bufferSize > 0)
		{
			buffer = new char[bufferSize];
			out.rdbuf()->setbuf(buffer, 0);
		}*/

		ofs.open(T2A(fileName.c_str()), (fileAppend ? std::ios::app :
			std::ios::trunc)|std::ios::out);

		if(!ofs.is_open())
		{
			errorHandler->error(_T("Unable to open file: ") + fileName);
			return;
		}

		this->os = &ofs;
		writeHeader();
		LogLog::debug(_T("FileAppender::activateOptions ended"));	}
	else
	{
		LogLog::warn(_T("File option not set for appender [")+name+_T("]."));
		LogLog::warn(_T("Are you using FileAppender instead of ConsoleAppender?"));
	}
}


