/***************************************************************************
                          mdc.h  -  class MDC
                             -------------------
    begin                : jeu avr 17 2003
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

#ifndef _LOG4CXX_MDC_H
#define _LOG4CXX_MDC_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/threadspecificdata.h>
#include <map>

namespace log4cxx
{
	/**
	The MDC class is similar to the {@link NDC} class except that it is
	based on a map instead of a stack. It provides <em>mapped
	diagnostic contexts</em>. A <em>Mapped Diagnostic Context</em>, or
	MDC in short, is an instrument for distinguishing interleaved log
	output from different sources. Log output is typically interleaved
	when a server handles multiple clients near-simultaneously.

	<p><b><em>The MDC is managed on a per thread basis</em></b>. A
	child thread automatically inherits a <em>copy</em> of the mapped
	diagnostic context of its parent.

	<p>The MDC class requires JDK 1.2 or above. Under JDK 1.1 the MDC
	will always return empty values but otherwise will not affect or
	harm your application.
	*/
	class MDC
	{
	public:
		/** tstring to string stl mp
		*/
		typedef std::map<tstring, tstring> Map;

	private:
		MDC();
		static Map * getCurrentThreadMap();
		static void setCurrentThreadMap(Map * map);

		static helpers::ThreadSpecificData threadSpecificData;

	public:
		/**
		* Put a context value (the <code>o</code> parameter) as identified
		* with the <code>key</code> parameter into the current thread's
		* context map.
		*
		* <p>If the current thread does not have a context map it is
		* created as a side effect.
		* */
  		static void put(const tstring& key, const tstring& value);

		/**
		* Get the context identified by the <code>key</code> parameter.
		*
		*  <p>This method has no side effects.
		* */
		static tstring get(const tstring& key);

		/**
		* Remove the the context identified by the <code>key</code>
		* parameter. */
		static tstring remove(const tstring& key);

		/**
		* Clear all entries in the MDC.
		*/
		static void clear();

		/**
		* Get the current thread's MDC as a Map. This method is
		* intended to be used internally.
		* */
		static const Map getContext();
	}; // class MDC;
}; // namespace log4cxx

#endif // _LOG4CXX_MDC_H
