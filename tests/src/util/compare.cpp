/***************************************************************************
                          compare.cpp

	begin                : 2003/12/02
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/
 /***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include "compare.h"
#include <fstream>

typedef std::basic_ifstream<TCHAR> ifstream;

using namespace log4cxx;

bool Compare::compare(const String& file1, const String& file2)
{
	USES_CONVERSION
	ifstream in1(T2A(file1.c_str()));
	ifstream in2(T2A(file2.c_str()));

	String s1;
	int lineCounter = 0;

	while (!std::getline(in1, s1).fail())
	{
		lineCounter++;

		String s2;
		std::getline(in2, s2);

		if (s1 != s2)
		{
			tcout << _T("Files [") << file1 << _T("] and [") << file2
				<< _T("] differ on line ") << lineCounter << std::endl;
			tcout << _T("One reads:  [") << s1 << _T("].") << std::endl;
			tcout << _T("Other reads:[") << s2 << _T("].") << std::endl;
			outputFile(file1);
			outputFile(file2);

			return false;
		}
	}

	// the second file is longer
	if (in2.get() != ifstream::traits_type::eof())
	{
		tcout << _T("File [") << file2 << _T("] longer than file [") << file1 << _T("].")
		<< std::endl;
		outputFile(file1);
		outputFile(file2);

		return false;
	}

	return true;
}

void Compare::outputFile(const String& file)
{
	USES_CONVERSION;
	ifstream in1(T2A(file.c_str()));

	String s1;
	int lineCounter = 0;
	tcout << _T("--------------------------------") << std::endl;
	tcout << _T("Contents of ") << file << _T(":") << std::endl;

	while (!std::getline(in1, s1).fail())
	{
		lineCounter++;
		tcout << lineCounter;

		if (lineCounter < 10)
		{
			tcout << _T("   : ");
		}
		else if (lineCounter < 100)
		{
			tcout << _T("  : ");
		}
		else if (lineCounter < 1000)
		{
			tcout << _T(" : ");
		}
		else
		{
			tcout << _T(": ");
		}

		tcout << s1 << std::endl;
	}
}
