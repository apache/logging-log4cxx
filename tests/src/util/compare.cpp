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

using namespace log4cxx;

bool Compare::compare(const String& file1, const String& file2)
{
	std::ifstream in1(file1.c_str());
	std::ifstream in2(file2.c_str());

	String s1;
	int lineCounter = 0;

	while (!std::getline(in1, s1).fail())
	{
		lineCounter++;

		String s2;
		std::getline(in2, s2);

		if (s1 != s2)
		{
			tcout << "Files [" << file1 << "] and [" << file2
				<< "] differ on line " << lineCounter << std::endl;
			tcout << "One reads:  [" << s1 << "]." << std::endl;
			tcout << "Other reads:[" << s2 << "]." << std::endl;
			outputFile(file1);
			outputFile(file2);

			return false;
		}
	}

	// the second file is longer
	if (in2.get() != std::ifstream::traits_type::eof())
	{
		tcout << "File [" << file2 << "] longer than file [" << file1 << "]."
		<< std::endl;
		outputFile(file1);
		outputFile(file2);

		return false;
	}

	return true;
}

void Compare::outputFile(const String& file)
{
	std::ifstream in1(file.c_str());

	String s1;
	int lineCounter = 0;
	tcout << "--------------------------------" << std::endl;
	tcout << "Contents of " << file << ":" << std::endl;

	while (!std::getline(in1, s1).fail())
	{
		lineCounter++;
		tcout << lineCounter;

		if (lineCounter < 10)
		{
			tcout << "   : ";
		}
		else if (lineCounter < 100)
		{
			tcout << "  : ";
		}
		else if (lineCounter < 1000)
		{
			tcout << " : ";
		}
		else
		{
			tcout << ": ";
		}

		tcout << s1 << std::endl;
	}
}
