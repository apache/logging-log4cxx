/***************************************************************************
                          filewatchdog.cpp  -  class FileWatchdog
                             -------------------
    begin                : jeu may 15 2003
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

#include <log4cxx/helpers/filewatchdog.h>
#include <log4cxx/helpers/loglog.h>
#include <sys/stat.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

long FileWatchdog::DEFAULT_DELAY = 60000; 

FileWatchdog::FileWatchdog(const tstring& filename)
 : filename(filename), lastModif(0), delay(DEFAULT_DELAY),
warnedAlready(false), interrupted(false)
{
	checkAndConfigure();
}

void FileWatchdog::checkAndConfigure()
{
	struct stat fileStats;

	USES_CONVERSION
	if (!::stat(T2A(filename.c_str()), &fileStats))
	{
		if (errno == ENOENT)
		{
			if(!warnedAlready) 
			{
				LogLog::debug(_T("[")+filename+_T("] does not exist."));
				warnedAlready = true;
			}
		}
		else
		{
			LogLog::warn(_T("Was not able to read check file existance, file:[")+
				filename+_T("]."));
			interrupted = true; // there is no point in continuing
		}
	}
	else
	{
		if (fileStats.st_mtime > lastModif)
		{ 
			lastModif = fileStats.st_mtime;
			doOnChange();
			warnedAlready = false;
		}
	}
}

void FileWatchdog::run()
{    
    while(!interrupted) 
	{
		Thread::sleep(delay);
		checkAndConfigure();
    }
}
