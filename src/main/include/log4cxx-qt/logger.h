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

#ifndef _LOG4CXX_QT_LOGGER_H
#define _LOG4CXX_QT_LOGGER_H
#include <log4cxx/logger.h>
#include <QString>

#if LOG4CXX_LOGCHAR_IS_UTF8
#define LOG4CXX_DECODE_QSTRING(var, src) \
	log4cxx::LogString var = (src).toStdString()

#define LOG4CXX_ENCODE_QSTRING(var, src) \
	QString var = QString::fromStdString(src)
#endif // LOG4CXX_LOGCHAR_IS_UTF8

#if LOG4CXX_LOGCHAR_IS_WCHAR
#define LOG4CXX_DECODE_QSTRING(var, src) \
	log4cxx::LogString var = (src).toStdWString()

#define LOG4CXX_ENCODE_QSTRING(var, src) \
	QString var = QString::fromStdWString(src)
#endif // LOG4CXX_LOGCHAR_IS_WCHAR

#if LOG4CXX_LOGCHAR_IS_UNICHAR
#define LOG4CXX_DECODE_QSTRING(var, src) \
	log4cxx::LogString var = (src).utf16()

#define LOG4CXX_ENCODE_QSTRING(var, src) \
	QString var = QString::fromUtf16((char16_t*)src.c_str())
#endif // LOG4CXX_LOGCHAR_IS_UNICHAR

#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
log4cxx::helpers::UniCharMessageBuffer& operator<<(log4cxx::helpers::UniCharMessageBuffer& mb, const QString& msg)
{
	return mb << msg.utf16();
}

#if LOG4CXX_WCHAR_T_API
log4cxx::helpers::WideMessageBuffer& operator<<(log4cxx::helpers::WideMessageBuffer& mb, const QString& msg)
{
	return mb << msg.toStdWString();
}

log4cxx::helpers::WideMessageBuffer& operator<<(log4cxx::helpers::MessageBuffer& mb, const QString& msg)
{
	return mb << msg.toStdWString();
}
#else // !LOG4CXX_WCHAR_T_API
log4cxx::helpers::UniCharMessageBuffer& operator<<(log4cxx::helpers::MessageBuffer& mb, const QString& msg)
{
	return mb << msg.utf16();
}
#endif // !LOG4CXX_WCHAR_T_API

#else // !(LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR)

#if LOG4CXX_WCHAR_T_API
log4cxx::helpers::WideMessageBuffer& operator<<(log4cxx::helpers::WideMessageBuffer& mb, const QString& msg)
{
	return mb << msg.toStdWString();
}

log4cxx::helpers::WideMessageBuffer& operator<<(log4cxx::helpers::MessageBuffer& mb, const QString& msg)
{
	return mb << msg.toStdWString();
}
#else // !LOG4CXX_WCHAR_T_API
log4cxx::helpers::CharMessageBuffer& operator<<(log4cxx::helpers::CharMessageBuffer& mb, const QString& msg)
{
	LOG4CXX_DECODE_QSTRING(tmp, msg);
	return mb << tmp;
}
#endif // !LOG4CXX_WCHAR_T_API

#endif // !(LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR)

#endif // _LOG4CXX_QT_LOGGER_H
