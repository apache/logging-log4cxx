/***************************************************************************
                          exception.h  -  class Exception
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

#ifndef _LOG4CXX_HELPERS_EXCEPTION_H
#define _LOG4CXX_HELPERS_EXCEPTION_H

#include <log4cxx/helpers/tchar.h>

namespace log4cxx
{
	namespace helpers
	{
		/** The class Exception and its subclasses indicate conditions that a
		reasonable application might want to catch.
		*/
		class LOG4CXX_EXPORT Exception
		{
		public:
			Exception() {}
			Exception(const String& message): message(message) {}
			inline const String& getMessage() { return message; }
			
		protected:
			String message;
			
	}; // class Exception

		/** RuntimeException is the parent class of those exceptions that can be
		thrown during the normal operation of the process.
		*/
		class LOG4CXX_EXPORT RuntimeException : public Exception
		{
		public:
			RuntimeException() {}
			RuntimeException(const String& message)
			 : Exception(message) {}
		}; // class RuntimeException

		/** Thrown when an application attempts to use null in a case where an
		object is required.
		*/
		class LOG4CXX_EXPORT  NullPointerException : public RuntimeException
		{
		public:
			NullPointerException() {}
			NullPointerException(const String& message)
			 : RuntimeException(message) {}
		}; // class NullPointerException

		/** Thrown to indicate that a method has been passed 
		an illegal or inappropriate argument.*/
		class LOG4CXX_EXPORT IllegalArgumentException : public RuntimeException
		{
		public:
			IllegalArgumentException(const String& message)
			 : RuntimeException(message) {}
		}; // class IllegalArgumentException
		
		/** Signals that an I/O exception of some sort has occurred. This class
		is the general class of exceptions produced by failed or interrupted
		I/O operations.
		*/
		class LOG4CXX_EXPORT IOException : public Exception
		{
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_EXCEPTION_H
