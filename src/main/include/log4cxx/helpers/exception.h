/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LOG4CXX_HELPERS_EXCEPTION_H
#define _LOG4CXX_HELPERS_EXCEPTION_H

#include <exception>
#include <log4cxx/log4cxx.h>
#include <log4cxx/logstring.h>
#include <string>

#ifdef _MSC_VER
	#pragma warning ( push )
	#pragma warning (disable : 4275) // ::std::exception needs to have dll-interface
	#pragma warning (disable : 4251) // ::std::basic_string needs to have dll-interface
#endif

namespace LOG4CXX_NS
{
namespace helpers
{
/** The class Exception and its subclasses indicate conditions that a
reasonable application might want to catch.
*/
class LOG4CXX_EXPORT Exception : public ::std::exception
{
	public:
		Exception(const char* msg);
		Exception(const LogString& msg);
		const char* what() const noexcept override;
		static LogString makeMessage(const LogString& type, log4cxx_status_t stat);
#if !LOG4CXX_LOGCHAR_IS_UTF8
		static std::string makeMessage(const char* type, log4cxx_status_t stat);
#endif
	private:
		std::string msg;
}; // class Exception

/** RuntimeException is the parent class of those exceptions that can be
thrown during the normal operation of the process.
*/
class LOG4CXX_EXPORT RuntimeException : public Exception
{
	public:
		RuntimeException(log4cxx_status_t stat);
		RuntimeException(const LogString& msg);
	private:
		static LogString formatMessage(log4cxx_status_t stat);
}; // class RuntimeException

/** Thrown when an application attempts to use null in a case where an
object is required.
*/
class LOG4CXX_EXPORT  NullPointerException : public RuntimeException
{
	public:
		NullPointerException(const LogString& msg);
}; // class NullPointerException

/** Thrown to indicate that a method has been passed
an illegal or inappropriate argument.*/
class LOG4CXX_EXPORT IllegalArgumentException : public RuntimeException
{
	public:
		IllegalArgumentException(const LogString& msg);
}; // class IllegalArgumentException

/** Signals that an I/O exception of some sort has occurred. This class
is the general class of exceptions produced by failed or interrupted
I/O operations.
*/
class LOG4CXX_EXPORT IOException : public Exception
{
	public:
		IOException();
		IOException(log4cxx_status_t stat);
		IOException(const LogString& msg);
		IOException(const char* msg);
		IOException(const LogString& type, log4cxx_status_t stat);
#if !LOG4CXX_LOGCHAR_IS_UTF8
		IOException(const char* msg, log4cxx_status_t stat);
#endif
	private:
		static LogString formatMessage(log4cxx_status_t stat);
};

class LOG4CXX_EXPORT SubProcessFailure : public Exception
{
	public:
		SubProcessFailure(const LogString& processName, int exitCode, int exitWhy);
#if !LOG4CXX_LOGCHAR_IS_UTF8
		SubProcessFailure(const char* processName, int exitCode, int exitWhy);
#endif
		static LogString makeMessage(const LogString& processName, int exitCode, int exitWhy);
};

class LOG4CXX_EXPORT MissingResourceException : public Exception
{
	public:
		MissingResourceException(const LogString& key);
	private:
		static LogString formatMessage(const LogString& key);
};

class LOG4CXX_EXPORT PoolException : public Exception
{
	public:
		PoolException(log4cxx_status_t stat);
	private:
		static LogString formatMessage(log4cxx_status_t stat);
};

/**
Thrown when an application tries to create an instance of a class using
the newInstance method in class Class, but the specified class object
cannot be instantiated because it is an interface or is an abstract class.
*/
class LOG4CXX_EXPORT InstantiationException : public Exception
{
	public:
		InstantiationException(const LogString& msg);
};

/**
Thrown when an application tries to load in a class through its
string name but no definition for the class with the specified name
could be found.
*/
class LOG4CXX_EXPORT ClassNotFoundException : public Exception
{
	public:
		ClassNotFoundException(const LogString& className);
	private:
		static LogString formatMessage(const LogString& className);
};


class LOG4CXX_EXPORT NoSuchElementException : public Exception
{
	public:
		NoSuchElementException();
};

class LOG4CXX_EXPORT IllegalStateException : public Exception
{
	public:
		IllegalStateException();
};

/** Thrown to indicate that there is an error in the underlying
protocol, such as a TCP error.
*/
class LOG4CXX_EXPORT SocketException : public IOException
{
	public:
		SocketException(const LogString& msg);
		SocketException(log4cxx_status_t status);
};

/** Signals that an error occurred while attempting to connect a socket
to a remote address and port. Typically, the connection was refused
remotely (e.g., no process is listening on the remote address/port).
*/
class LOG4CXX_EXPORT ConnectException : public SocketException
{
	public:
		ConnectException(const LogString& msg);
		ConnectException(log4cxx_status_t status);
};

class LOG4CXX_EXPORT ClosedChannelException : public SocketException
{
	public:
		ClosedChannelException();
};

/** Signals that an error occurred while attempting to bind a socket to
a local address and port. Typically, the port is in use, or the
requested local address could not be assigned.
*/
class LOG4CXX_EXPORT BindException : public SocketException
{
	public:
		BindException(log4cxx_status_t status);
};

/** Signals that an I/O operation has been interrupted. An
InterruptedIOException is thrown to indicate that an input or output
transfer has been terminated because the thread performing it was
interrupted. The field bytesTransferred  indicates how many bytes were
successfully transferred before the interruption occurred.
*/
class LOG4CXX_EXPORT InterruptedIOException : public IOException
{
	public:
		InterruptedIOException(const LogString& msg);
};


/** Signals that an I/O operation has been interrupted. An
InterruptedIOException is thrown to indicate that an input or output
transfer has been terminated because the thread performing it was
interrupted. The field bytesTransferred  indicates how many bytes were
successfully transferred before the interruption occurred.
*/
class LOG4CXX_EXPORT SocketTimeoutException : public InterruptedIOException
{
	public:
		SocketTimeoutException();
};


}  // namespace helpers
} // namespace log4cxx

#if defined(_MSC_VER)
	#pragma warning (pop)
#endif

#endif // _LOG4CXX_HELPERS_EXCEPTION_H
