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

#ifndef _LOG4CXX_QT_TRANSCODER_H
#define _LOG4CXX_QT_TRANSCODER_H
#include <log4cxx/logstring.h>
#include <QString>

#if LOG4CXX_LOGCHAR_IS_UTF8
/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the QString \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The QString variable.
*/
#define LOG4CXX_DECODE_QSTRING(var, src) \
	LOG4CXX_NS::LogString var = (src).toStdString()

/** Create a QString equivalent of \c src.

	Defines a QString variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new QString variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_QSTRING(var, src) \
	QString var = QString::fromStdString(src)
#endif // LOG4CXX_LOGCHAR_IS_UTF8

#if LOG4CXX_LOGCHAR_IS_WCHAR
/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the QString \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The QString variable.
*/
#define LOG4CXX_DECODE_QSTRING(var, src) \
	LOG4CXX_NS::LogString var = (src).toStdWString()

/** Create a QString equivalent of \c src.

	Defines a QString variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new QString variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_QSTRING(var, src) \
	QString var = QString::fromStdWString(src)
#endif // LOG4CXX_LOGCHAR_IS_WCHAR

#if LOG4CXX_LOGCHAR_IS_UNICHAR
/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the QString \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The QString variable.
*/
#define LOG4CXX_DECODE_QSTRING(var, src) \
	LOG4CXX_NS::LogString var = (src).utf16()

/** Create a QString equivalent of \c src.

	Defines a QString variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new QString variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_QSTRING(var, src) \
	QString var = QString::fromUtf16((char16_t*)src.c_str())
#endif // LOG4CXX_LOGCHAR_IS_UNICHAR

#endif // _LOG4CXX_QT_TRANSCODER_H
