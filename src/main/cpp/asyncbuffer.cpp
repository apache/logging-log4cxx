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

#include <log4cxx/helpers/asyncbuffer.h>
#include <log4cxx/helpers/transcoder.h>

namespace LOG4CXX_NS
{

namespace helpers
{

struct AsyncBuffer::Private
{
	std::vector<MessageBufferAppender> data;

	Private(const MessageBufferAppender& f)
		: data{ f }
	{}

#if LOG4CXX_ASYNC_BUFFER_SUPPORTS_FMT
	StringViewType fmt_string;
	FmtArgStore    fmt_args;

	Private(StringViewType&& format_string, FmtArgStore&& args)
		: fmt_string{ std::move(format_string) }
		, fmt_args{ std::move(args) }
	{}

#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
	WideStringViewType fmt_wstring;
	WideFmtArgStore    fmt_wargs;

	Private(WideStringViewType&& format_string, WideFmtArgStore&& args)
		: fmt_wstring{ std::move(format_string) }
		, fmt_wargs{ std::move(args) }
	{}
#endif // LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
#endif // LOG4CXX_ASYNC_BUFFER_SUPPORTS_FMT

};

#if LOG4CXX_ASYNC_BUFFER_SUPPORTS_FMT
void AsyncBuffer::initializeForFmt(StringViewType&& format_string, FmtArgStore&& args)
{
	if (!m_priv)
		m_priv = std::make_unique<Private>(std::move(format_string), std::move(args));
	else
	{
		m_priv->fmt_string = std::move(format_string);
		m_priv->fmt_args = std::move(args);
	}
}

#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
void AsyncBuffer::initializeForFmt(WideStringViewType&& format_string, WideFmtArgStore&& args)
{
	if (!m_priv)
		m_priv = std::make_unique<Private>(std::move(format_string), std::move(args));
	else
	{
		m_priv->fmt_wstring = std::move(format_string);
		m_priv->fmt_wargs = std::move(args);
	}
}
#endif // LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
#endif // LOG4CXX_ASYNC_BUFFER_SUPPORTS_FMT

/** An empty buffer.
*/
AsyncBuffer::AsyncBuffer()
{}

/** A new buffer with the content of \c other
*/
AsyncBuffer::AsyncBuffer(AsyncBuffer&& other)
	: m_priv(std::move(other.m_priv))
{
}

/** Release resources.
*/
AsyncBuffer::~AsyncBuffer()
{
}

/**
* Has no item been added to this?
*/
bool AsyncBuffer::empty() const
{
	bool result{ true };
	if (m_priv)
	{
		result = m_priv->data.empty();
#if LOG4CXX_ASYNC_BUFFER_SUPPORTS_FMT
		if (result)
			result = (0 == m_priv->fmt_string.size());
#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
		if (result)
			result = (0 == m_priv->fmt_wstring.size());
#endif // LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
#endif
	}
	return result;
}

/**
* Add text version of buffered values to \c msg
*/
void AsyncBuffer::renderMessage(LogCharMessageBuffer& msg) const
{
	if (m_priv)
	{
		for (auto& renderer : m_priv->data)
			renderer(msg);
#if LOG4CXX_ASYNC_BUFFER_SUPPORTS_FMT
#if LOG4CXX_LOGCHAR_IS_UTF8
		if (0 < m_priv->fmt_string.size())
			msg << fmt::vformat(m_priv->fmt_string, m_priv->fmt_args);
#if LOG4CXX_WCHAR_T_API
		if (0 < m_priv->fmt_wstring.size())
		{
			LOG4CXX_DECODE_WCHAR(lsMsg, fmt::vformat(m_priv->fmt_wstring, m_priv->fmt_wargs));
			msg << lsMsg;
		}
#endif // LOG4CXX_WCHAR_T_API
#endif // LOG4CXX_LOGCHAR_IS_UTF8

#if LOG4CXX_LOGCHAR_IS_WCHAR
		if (0 < m_priv->fmt_wstring.size())
			msg << fmt::vformat(m_priv->fmt_wstring, m_priv->fmt_wargs);
		if (0 < m_priv->fmt_string.size())
		{
			LOG4CXX_DECODE_CHAR(lsMsg, fmt::vformat(m_priv->fmt_string, m_priv->fmt_args));
			msg << lsMsg;
		}
#endif // LOG4CXX_LOGCHAR_IS_WCHAR
#endif // LOG4CXX_ASYNC_BUFFER_SUPPORTS_FMT
	}
}

/**
* Remove all message appenders
*/
void AsyncBuffer::clear()
{
	if (m_priv)
	{
		m_priv->data.clear();
#if LOG4CXX_ASYNC_BUFFER_SUPPORTS_FMT
		m_priv->fmt_string = {};
#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
		m_priv->fmt_wstring = {};
#endif // LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
#endif // LOG4CXX_ASYNC_BUFFER_SUPPORTS_FMT
	}
}

/**
 *   Append \c function to this buffer.
 */
void AsyncBuffer::append(const MessageBufferAppender& f)
{
	if (!m_priv)
		m_priv = std::make_unique<Private>(f);
	else
		m_priv->data.push_back(f);
}

} // namespace helpers
} // namespace LOG4CXX_NS

