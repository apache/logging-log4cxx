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

#ifndef _LOG4CXX_QT_MESSAGE_BUFFER_H
#define _LOG4CXX_QT_MESSAGE_BUFFER_H
#include <log4cxx-qt/transcoder.h>

#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
	inline LOG4CXX_NS::helpers::UniCharMessageBuffer&
operator<<(LOG4CXX_NS::helpers::UniCharMessageBuffer& mb, const QString& msg)
{
	return mb << msg.utf16();
}

#if LOG4CXX_WCHAR_T_API
	inline LOG4CXX_NS::helpers::WideMessageBuffer&
operator<<(LOG4CXX_NS::helpers::WideMessageBuffer& mb, const QString& msg)
{
	return mb << msg.toStdWString();
}

	inline LOG4CXX_NS::helpers::WideMessageBuffer&
operator<<(LOG4CXX_NS::helpers::MessageBuffer& mb, const QString& msg)
{
	return mb << msg.toStdWString();
}
#else // !LOG4CXX_WCHAR_T_API
	inline LOG4CXX_NS::helpers::UniCharMessageBuffer&
operator<<(LOG4CXX_NS::helpers::MessageBuffer& mb, const QString& msg)
{
	return mb << msg.utf16();
}
#endif // !LOG4CXX_WCHAR_T_API

#else // !(LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR)

#if LOG4CXX_WCHAR_T_API
	inline LOG4CXX_NS::helpers::WideMessageBuffer&
operator<<(LOG4CXX_NS::helpers::WideMessageBuffer& mb, const QString& msg)
{
	return mb << msg.toStdWString();
}

	inline LOG4CXX_NS::helpers::WideMessageBuffer&
operator<<(LOG4CXX_NS::helpers::MessageBuffer& mb, const QString& msg)
{
	return mb << msg.toStdWString();
}
#else // !LOG4CXX_WCHAR_T_API
	inline LOG4CXX_NS::helpers::CharMessageBuffer&
operator<<(LOG4CXX_NS::helpers::CharMessageBuffer& mb, const QString& msg)
{
	LOG4CXX_DECODE_QSTRING(tmp, msg);
	return mb << tmp;
}
#endif // !LOG4CXX_WCHAR_T_API

#endif // !(LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR)

#endif // _LOG4CXX_QT_MESSAGE_BUFFER_H
