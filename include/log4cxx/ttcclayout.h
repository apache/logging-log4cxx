/***************************************************************************
                          ttcclayout.h  -  class TTCCLayout
                             -------------------
    begin                : dim avr 20 2003
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

#ifndef _LOG4CXX_TTCC_LAYOUT_H
#define _LOG4CXX_TTCC_LAYOUT_H

#include <log4cxx/helpers/datelayout.h>

namespace log4cxx
{
	class TTCCLayout;
	typedef helpers::ObjectPtrT<TTCCLayout> TTCCLayoutPtr;

    /**
    TTCC layout format consists of time, thread, category and nested
    diagnostic context information, hence the name.

    <p>Each of the four fields can be individually enabled or
    disabled. The time format depends on the <code>DateFormat</code>
    used.

    <p>Here is an example TTCCLayout output with the
    {@link helpers::RelativeTimeDateFormat RelativeTimeDateFormat}.

    <pre>
    176 [main] INFO  examples.Sort - Populating an array of 2 elements in reverse order.
    225 [main] INFO  examples.SortAlgo - Entered the sort method.
    262 [main] DEBUG examples.SortAlgo.OUTER i=1 - Outer loop.
    276 [main] DEBUG examples.SortAlgo.SWAP i=1 j=0 - Swapping intArray[0] = 1 and intArray[1] = 0
    290 [main] DEBUG examples.SortAlgo.OUTER i=0 - Outer loop.
    304 [main] INFO  examples.SortAlgo.DUMP - Dump of interger array:
    317 [main] INFO  examples.SortAlgo.DUMP - Element [0] = 0
    331 [main] INFO  examples.SortAlgo.DUMP - Element [1] = 1
    343 [main] INFO  examples.Sort - The next log statement should be an error message.
    346 [main] ERROR examples.SortAlgo.DUMP - Tried to dump an uninitialized array.
    467 [main] INFO  examples.Sort - Exiting main method.
    </pre>

    <p>The first field is the number of milliseconds elapsed since the
    start of the program. The second field is the thread outputting the
    log statement. The third field is the level, the fourth field is
    the category to which the statement belongs.

    <p>The fifth field (just before the '-') is the nested diagnostic
    context.  Note the nested diagnostic context may be empty as in the
    first two statements. The text after the '-' is the message of the
    statement.

    <p><b>WARNING</b> Do not use the same TTCCLayout instance from
    within different appenders. The TTCCLayout is not thread safe when
    used in his way. However, it is perfectly safe to use a TTCCLayout
    instance from just one appender.

    <p>PatternLayout offers a much more flexible alternative.
    */
	class TTCCLayout : public helpers::DateLayout
	{
	private:
		  // Internal representation of options
		  bool threadPrinting;
		  bool categoryPrefixing;
		  bool contextPrinting;
		  bool filePrinting;

	public:
		DECLARE_LOG4CXX_OBJECT(TTCCLayout)
		BEGIN_LOG4CXX_INTERFACE_MAP()
			LOG4CXX_INTERFACE_ENTRY(TTCCLayout)
			LOG4CXX_INTERFACE_ENTRY_CHAIN(Layout)
		END_LOG4CXX_INTERFACE_MAP()

	/**
	Instantiate a TTCCLayout object with {@link
	helpers::RelativeTimeDateFormat RelativeTimeDateFormat} as the date
	formatter in the local time zone.
	*/
		TTCCLayout();

	/**
	Instantiate a TTCCLayout object using the local time zone. The
	DateFormat used will depend on the <code>dateFormatType</code>.
	<p>This constructor just calls the {@link
	helpers::DateLayout#setDateFormat DateLayout::setDateFormat} method.
	*/
		TTCCLayout(const tstring& dateFormatType);

	/**
	The <b>ThreadPrinting</b> option specifies whether the name of the
	current thread is part of log output or not. This is true by default.
	*/
		inline void setThreadPrinting(bool threadPrinting)
			{ this->threadPrinting = threadPrinting; }

	/**
	Returns value of the <b>ThreadPrinting</b> option.
	*/
		inline bool getThreadPrinting() const
			{ return threadPrinting; }

	/**
	The <b>CategoryPrefixing</b> option specifies whether Logger
	name is part of log output or not. This is true by default.
	*/
		inline void setCategoryPrefixing(bool categoryPrefixing)
			{ this->categoryPrefixing = categoryPrefixing; }

	/**
	Returns value of the <b>CategoryPrefixing</b> option.
	*/
		inline bool getCategoryPrefixing() const
			{ return categoryPrefixing; }

	/**
	The <b>ContextPrinting</b> option specifies log output will include
	the nested context information belonging to the current thread.
	This is true by default.
	*/
		inline void setContextPrinting(bool contextPrinting)
			{ this->contextPrinting = contextPrinting; }

	/**
	Returns value of the <b>ContextPrinting</b> option.
	*/
		inline bool getContextPrinting() const
			{ return contextPrinting; }

	/**
	The <b>FilePrinting</b> option specifies log output will include
	the file and the line where the log statement was written.
	*/
		inline void setFilePrinting(bool filePrinting)
			{ this->filePrinting = filePrinting; }

	/**
	Returns value of the <b>ContextPrinting</b> option.
	*/
		inline bool getFilePrinting() const
			{ return filePrinting; }
			
	/**
	In addition to the level of the statement and message, this function
	writes to the ouput stream time, thread, category and NDC
	information.

	<p>Time, thread, category and diagnostic context are printed
	depending on options.

	@param output
	@param event
	*/
	virtual void format(tostream& output, const spi::LoggingEvent& event);

	/**
	The TTCCLayout does not handle the throwable contained within
	{@link spi::LoggingEvent LoggingEvents}. Thus, it returns
	<code>true</code>.
	*/
	virtual bool ignoresThrowable() { return true; }
	};
};

#endif
