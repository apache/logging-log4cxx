/***************************************************************************
                          formattinginfo.cpp  -  class FormattingInfo
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

#include <log4cxx/helpers/formattinginfo.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx::helpers;

FormattingInfo::FormattingInfo()
{ 
	reset();
}

void FormattingInfo::reset()
{
	minChar = -1;
	maxChar = 0x7FFFFFFF;
	leftAlign = false;      
}

void FormattingInfo::dump()
{
	LOGLOG_DEBUG(_T("minChar=") << minChar 
		<< _T(", maxChar=") << maxChar
		<< _T(", leftAlign=") << leftAlign);
}



