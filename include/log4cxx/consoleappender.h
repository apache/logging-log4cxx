/***************************************************************************
                          consoleappender.h  -  class ConsoleAppender
                             -------------------
    begin                : mar avr 15 2003
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

#ifndef _LOG4CXX_CONSOLE_APPENDER_H
#define _LOG4CXX_CONSOLE_APPENDER_H

#include <log4cxx/writerappender.h>

namespace log4cxx
{
	/**
	* ConsoleAppender appends log events to <code>stdout</code> or
	* <code>stderr</code> using a layout specified by the user. The
	* default target is <code>stdout</code>.
	*/
	class ConsoleAppender : public WriterAppender
	{
	public:
		ConsoleAppender();
		ConsoleAppender(LayoutPtr layout);
		ConsoleAppender(LayoutPtr layout, const tstring& target);
		~ConsoleAppender();

	/**
	*  This method overrides the parent
	*  WriterAppender#closeWriter implementation to do nothing because
	*  the console stream is not ours to close.
	* */
	protected:
		virtual void closeWriter() {}

	/**
	*  Sets the value of the <b>#target</b> property. Recognized values
	*  are "System.out" and "System.err". Any other value will be
	*  ignored.
	* */
	public:
		void setTarget(const tstring& value);

	/**
	* Returns the current value of the <b>#target</b> property. The
	* default value of the option is "System.out".
	*
	* See also #setTarget.
	* */
	public:
		const tstring& getTarget();

	protected:
		void targetWarn(const tstring& val);

	public:
		void activateOptions();
		void setOption(const tstring& option, const tstring& value);

	public:
		static tstring SYSTEM_OUT;
		static tstring SYSTEM_ERR;

	protected:
		tstring target;
	};
}; //namespace log4cxx

#endif //_LOG4CXX_CONSOLE_APPENDER_H

