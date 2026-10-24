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
#define __STDC_WANT_LIB_EXT1__ 1
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/exception.h>
#include <string.h>
#include <string>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <apr_errno.h>
#include <apr_thread_proc.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

Exception::Exception(const LogString& msg1)
{
	LOG4CXX_ENCODE_CHAR(m, msg1);
	msg = m;
}

Exception::Exception(const char* m)
{
	msg = (m ? std::string(m) : std::string());
}

const char* Exception::what() const noexcept
{
	return msg.c_str();
}

RuntimeException::RuntimeException(log4cxx_status_t stat)
	: Exception(formatMessage(stat))
{
}

RuntimeException::RuntimeException(const LogString& msg1)
	: Exception(msg1)
{
}

LogString RuntimeException::formatMessage(log4cxx_status_t stat)
{
	LogString s(LOG4CXX_STR("RuntimeException: return code = "));
	StringHelper::toString(stat, s);
	return s;
}

NullPointerException::NullPointerException(const LogString& msg1)
	: RuntimeException(msg1 + LOG4CXX_STR(" may not be null"))
{
}

IllegalArgumentException::IllegalArgumentException(const LogString& msg1)
	: RuntimeException(msg1)
{
}

IOException::IOException()
	: Exception(LOG4CXX_STR("IO exception"))
{
}

IOException::IOException(log4cxx_status_t stat)
	: Exception(formatMessage(stat))
{
}

IOException::IOException(const LogString& type, log4cxx_status_t stat)
	: Exception(makeMessage(type, stat))
{
}

#if !LOG4CXX_LOGCHAR_IS_UTF8
IOException::IOException(const char* type, log4cxx_status_t stat)
	: Exception(makeMessage(type, stat).c_str())
{
}
#endif

IOException::IOException(const char* msg1)
	: Exception(msg1)
{
}

IOException::IOException(const LogString& msg1)
	: Exception(msg1)
{
}

LogString IOException::formatMessage(log4cxx_status_t stat)
{
	return makeMessage(LOG4CXX_STR("IO Exception"), stat);
}

SubProcessFailure::SubProcessFailure(const LogString& processName, int exitCode, int exitWhy)
	: Exception(makeMessage(processName, exitCode, exitWhy))
{
}

#if !LOG4CXX_LOGCHAR_IS_UTF8
SubProcessFailure::SubProcessFailure(const char* processName, int exitCode, int exitWhy)
	: Exception(makeMessage(Transcoder::decode(processName), exitCode, exitWhy))
{
}
#endif

LogString SubProcessFailure::makeMessage(const LogString& processName, int exitCode, int exitWhy)
{
	LogString msg = processName;
	msg += LOG4CXX_STR(" exit code: ");
	LogString codeStr;
	StringHelper::toString(exitCode, codeStr);
	msg += codeStr;
	if (APR_PROC_SIGNAL == exitWhy || APR_PROC_SIGNAL_CORE == exitWhy)
	{
		msg += LOG4CXX_STR("; exited due to a signal");
	}
	return msg;
}

LogString Exception::makeMessage(const LogString& type, log4cxx_status_t stat)
{
	LogString s = type;
	char err_buff[1024] = {0};
	apr_strerror(stat, err_buff, sizeof(err_buff));
	if (0 == err_buff[0] || 0 == strncmp(err_buff, "APR does not understand", 23))
	{
		s.append(LOG4CXX_STR(": error code "));
		StringHelper::toString(stat, s);
	}
	else
	{
		s.append(LOG4CXX_STR(" - "));
		std::string sMsg = err_buff;
		LOG4CXX_DECODE_CHAR(lsMsg, sMsg);
		s.append(lsMsg);
	}
	return s;
}

#if !LOG4CXX_LOGCHAR_IS_UTF8
std::string Exception::makeMessage(const char* type, log4cxx_status_t stat)
{
	std::string s = type;
	char err_buff[1024] = {0};
	apr_strerror(stat, err_buff, sizeof(err_buff));
	if (0 == err_buff[0] || 0 == strncmp(err_buff, "APR does not understand", 23))
	{
		s.append(": error code ");
		s.append(std::to_string(stat));
	}
	else
	{
		s.append(" - ");
		s.append(err_buff);
	}
	return s;
}
#endif

MissingResourceException::MissingResourceException(const LogString& key)
	: Exception(formatMessage(key))
{
}

LogString MissingResourceException::formatMessage(const LogString& key)
{
	LogString s(LOG4CXX_STR("MissingResourceException: resource key = \""));
	s.append(key);
	s.append(LOG4CXX_STR("\"."));
	return s;
}

PoolException::PoolException(log4cxx_status_t stat)
	: Exception(formatMessage(stat))
{
}

LogString PoolException::formatMessage(log4cxx_status_t stat)
{
	return makeMessage(LOG4CXX_STR("Pool exception"), stat);
}

InstantiationException::InstantiationException(const LogString& msg1)
	: Exception(msg1)
{
}

ClassNotFoundException::ClassNotFoundException(const LogString& className)
	: Exception(formatMessage(className))
{
}

LogString ClassNotFoundException::formatMessage(const LogString& className)
{
	LogString s(LOG4CXX_STR("Class not found: "));
	s.append(className);
	return s;
}


NoSuchElementException::NoSuchElementException()
	: Exception(LOG4CXX_STR("No such element"))
{
}

IllegalStateException::IllegalStateException()
	: Exception(LOG4CXX_STR("Illegal state"))
{
}

SocketException::SocketException(const LogString& msg) : IOException(msg)
{
}

SocketException::SocketException(log4cxx_status_t status) : IOException(status)
{
}

ConnectException::ConnectException(const LogString& msg) : SocketException(msg)
{
}

ConnectException::ConnectException(log4cxx_status_t status) : SocketException(status)
{
}

ClosedChannelException::ClosedChannelException() : SocketException(LOG4CXX_STR("Attempt to write to closed socket"))
{
}

BindException::BindException(log4cxx_status_t status) : SocketException(status)
{
}

InterruptedIOException::InterruptedIOException(const LogString& msg) : IOException(msg)
{
}

SocketTimeoutException::SocketTimeoutException()
	: InterruptedIOException(LOG4CXX_STR("SocketTimeoutException"))
{
}
