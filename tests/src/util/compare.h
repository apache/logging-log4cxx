/***************************************************************************
                          compare.h
                             -------------------
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

#include <log4cxx/helpers/tchar.h>

namespace log4cxx
{
	class Compare
	{
	public:
		static bool compare(const String& file1, const String& file2);

	private:
		/// Prints file on the console.
		static void outputFile(const String& file);
	};
};
