/***************************************************************************
                          patternparser.h  -  class PatternParser
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

#ifndef _LOG4CXX_HELPER_PATTERN_PARSER_H
#define _LOG4CXX_HELPER_PATTERN_PARSER_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/formattinginfo.h>
#include <log4cxx/helpers/patternconverter.h>

namespace log4cxx
{
	namespace spi
	{
		class LoggingEvent;
	};

	namespace helpers
	{

		class DateFormat;

	/**
	Most of the work of the PatternLayout class
	is delegated to the PatternParser class.
	
	<p>It is this class that parses conversion patterns and creates
	a chained list of {@link helpers::OptionConverter OptionConverters}.
	*/
		class PatternParser
		{
		protected:
			int state;
			StringBuffer currentLiteral;
			int patternLength;
			int i;
			PatternConverterPtr head;
			PatternConverterPtr tail;
			FormattingInfo formattingInfo;
			String pattern;
			String timeZone;

		public:
			PatternParser(const String& pattern, const String& timeZone);
			
		private:
			void addToList(PatternConverterPtr& pc);
			
		protected:
			String extractOption();
			
			/**
			The option is expected to be in decimal and positive. In case of
			error, zero is returned.  */
			int extractPrecisionOption();
			
		public:
			PatternConverterPtr parse();
			
		protected:
			void finalizeConverter(TCHAR c);

			void addConverter(PatternConverterPtr& pc);

		// ---------------------------------------------------------------------
		//                      PatternConverters
		// ---------------------------------------------------------------------
		private:
			class BasicPatternConverter : public PatternConverter
			{
			private:
				int type;
			public:
				BasicPatternConverter(const FormattingInfo& formattingInfo, int type);
				virtual void convert(ostream& sbuf, const spi::LoggingEvent& event);
			};

			class LiteralPatternConverter : public PatternConverter
			{
			private:
				String literal;

			public:
				LiteralPatternConverter(const String& value);
				virtual void format(StringBuffer& sbuf, const spi::LoggingEvent& e);
				virtual void convert(ostream& sbuf, const spi::LoggingEvent& event);
			};

			class DatePatternConverter : public PatternConverter
			{
			private:
				DateFormat * df;

			public:
				DatePatternConverter(const FormattingInfo& formattingInfo, DateFormat * df);
				~DatePatternConverter();
				
			public:
				virtual void convert(ostream& sbuf, const spi::LoggingEvent& event);
			};

			class MDCPatternConverter : public PatternConverter
			{
			private:
				String key;
			
			public:
				MDCPatternConverter(const FormattingInfo& formattingInfo, const String& key);
				virtual void convert(ostream& sbuf, const spi::LoggingEvent& event);
			};

			class LocationPatternConverter : public PatternConverter
			{
			private:
				int type;
			
			public:
				LocationPatternConverter(const FormattingInfo& formattingInfo, int type);
				virtual void convert(ostream& sbuf, const spi::LoggingEvent& event);
			};

			class CategoryPatternConverter : public PatternConverter
			{
			private:
				int precision;
			
			public:
				CategoryPatternConverter(const FormattingInfo& formattingInfo, int precision);
				virtual void convert(ostream& sbuf, const spi::LoggingEvent& event);
			};
		}; // class PatternParser
	}; // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPER_PATTERN_PARSER_H
