/***************************************************************************
                          patternconverter.h  -  class PatternConverter
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

#ifndef _LOG4CXX_HELPER_PATTERN_CONVERTER_H
#define _LOG4CXX_HELPER_PATTERN_CONVERTER_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/objectimpl.h>

namespace log4cxx
{
	namespace spi
	{
		class LoggingEvent;
	};

	namespace helpers
	{
		class FormattingInfo;

		class PatternConverter;
		typedef ObjectPtrT<PatternConverter> PatternConverterPtr;

		/**
		<p>PatternConverter is an abtract class that provides the
		formatting functionality that derived classes need.

		<p>Conversion specifiers in a conversion patterns are parsed to
		individual PatternConverters. Each of which is responsible for
		converting a logging event in a converter specific manner.
		*/
		class PatternConverter : public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(PatternConverter)
			BEGIN_LOG4CXX_INTERFACE_MAP()
				LOG4CXX_INTERFACE_ENTRY(PatternConverter)
			END_LOG4CXX_INTERFACE_MAP()

			PatternConverterPtr next;
			int min;
			int max;
			bool leftAlign;

		protected:
			PatternConverter();
			PatternConverter(const FormattingInfo& fi);

			/**
			Derived pattern converters must override this method in order to
			convert conversion specifiers in the correct way.
			*/
			virtual void convert(tostream& sbuf, const spi::LoggingEvent& event) = 0;

			static tstring SPACES[];

		public:
			/**
			A template method for formatting in a converter specific way.
			*/
			virtual void format(tostream& sbuf, const spi::LoggingEvent& e);

			/**
			Fast space padding method.
			*/
			void spacePad(tostream& sbuf, int length);

		}; // class PatternConverter
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPER_PATTERN_CONVERTER_H
