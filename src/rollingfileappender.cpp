/***************************************************************************
             rollingfileappender.cpp  -  class RollingFileAppender
                             -------------------
    begin                : mer avr 30 2003
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

#include <log4cxx/rollingfileappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(RollingFileAppender)

RollingFileAppender::RollingFileAppender()
: maxFileSize(10*1024*1024), maxBackupIndex(1)
{
}


RollingFileAppender::RollingFileAppender(const LayoutPtr& layout, const String& fileName, bool append)
: FileAppender(layout, fileName, append),
maxFileSize(10*1024*1024), maxBackupIndex(1)
{
}

RollingFileAppender::RollingFileAppender(const LayoutPtr& layout, const String& 
fileName) : FileAppender(layout, fileName),
maxFileSize(10*1024*1024), maxBackupIndex(1)
{
}

// synchronization not necessary since doAppend is alreasy synched
void RollingFileAppender::rollOver()
{
	LOGLOG_DEBUG(_T("rolling over count=") << ofs.tellp());
	LOGLOG_DEBUG(_T("maxBackupIndex=") << maxBackupIndex);

	// close and reset the current file
	ofs.close();
	ofs.clear();

	// If maxBackups <= 0, then there is no file renaming to be done.
	if(maxBackupIndex > 0)
	{
		// Delete the oldest file, to keep Windows happy.
		StringBuffer file;
		file << fileName << _T(".") << maxBackupIndex;
		USES_CONVERSION;
		remove(T2A(file.str().c_str()));

		// Map {(maxBackupIndex - 1), ..., 2, 1} to {maxBackupIndex, ..., 3, 2}
		for (int i = maxBackupIndex - 1; i >= 1; i--)
		{
			StringBuffer file;
			StringBuffer target;

			file << fileName << _T(".") << i;
			target << fileName << _T(".") << (i + 1);
			LogLog::debug(_T("Renaming file ") + file.str() + _T(" to ") + target.str());
			rename(T2A(file.str().c_str()), T2A(target.str().c_str()));
		}

		// Rename fileName to fileName.1
		StringBuffer target;
		target << fileName << _T(".") << 1;

		LogLog::debug(_T("Renaming file ") + fileName + _T(" to ") + target.str());
		rename(T2A(fileName.c_str()), T2A(target.str().c_str()));
	}

	// Open the current file up again in truncation mode
	USES_CONVERSION;
	ofs.open(T2A(fileName.c_str()), std::ios::out|std::ios::trunc);
	if(!ofs.is_open())
	{
		LogLog::error(_T("Unable to open file: ") + fileName);
	}
}

void RollingFileAppender::subAppend(const spi::LoggingEventPtr& event)
{
	FileAppender::subAppend(event);
	if(!fileName.empty() && ofs.tellp() >= maxFileSize)
	{
		rollOver();
	}
}

void RollingFileAppender::setOption(const String& option,
	const String& value)
{
	if (StringHelper::equalsIgnoreCase(option, _T("maxfilesize")) 
		|| StringHelper::equalsIgnoreCase(option, _T("maximumfilesize")))
	{
		setMaxFileSize(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, _T("maxbackupindex"))
		|| StringHelper::equalsIgnoreCase(option, _T("maximumbackupindex")))
	{
		maxBackupIndex = ttol(value.c_str());
	}
	else
	{
		FileAppender::setOption(option, value);
	}
}
