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

#include <log4cxx/log4cxx.h>
#include <log4cxx/helpers/messagebuffer.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/threadspecificdata.h>

using namespace LOG4CXX_NS::helpers;

namespace {

template <typename T>
struct StringOrStream
{
	std::basic_string<T> buf;
	std::basic_ostringstream<T>* stream;

	StringOrStream()
		: stream(nullptr)
		{}
	~StringOrStream()
	{
		if (this->stream)
			ThreadSpecificData::releaseStringStream<T>(*this->stream);
	}
	/**
	 * Move the character buffer from \c buf to \c stream
	 */
	std::basic_ostringstream<T>& StreamFromBuf()
	{
		if (!this->stream)
		{
			const static std::basic_ostringstream<T> initialState;
			auto& sStream = ThreadSpecificData::getStringStream<T>();
			this->stream = &sStream;
			this->stream->clear();
			this->stream->precision(initialState.precision());
			this->stream->width(initialState.width());
			this->stream->setf(initialState.flags(), ~initialState.flags());
			this->stream->fill(initialState.fill());
			auto index = this->buf.size();
			this->stream->str(std::move(this->buf));
			this->stream->seekp(index);
		}
		return *this->stream;
	}
	/**
	 * Move the character buffer from \c stream to \c buf
	 */
	std::basic_string<T>& BufFromStream()
	{
		if (this->stream)
		{
			this->buf = std::move(*this->stream).str();
			this->stream->seekp(0);
			this->stream->str(std::basic_string<T>());
			this->stream->clear();
		}
		return this->buf;
	}
};
}

struct CharMessageBuffer::CharMessageBufferPrivate : public StringOrStream<char> {};

CharMessageBuffer::CharMessageBuffer() : m_priv(std::make_unique<CharMessageBufferPrivate>())
{
}

CharMessageBuffer::~CharMessageBuffer()
{
}

CharMessageBuffer& CharMessageBuffer::operator<<(const std::basic_string<char>& msg)
{
	if (m_priv->stream == 0)
	{
		m_priv->buf.append(msg);
	}
	else
	{
		*m_priv->stream << msg;
	}

	return *this;
}

CharMessageBuffer& CharMessageBuffer::operator<<(const char* msg)
{
	const char* actualMsg = msg;

	if (actualMsg == 0)
	{
		actualMsg = "null";
	}

	if (m_priv->stream == 0)
	{
		m_priv->buf.append(actualMsg);
	}
	else
	{
		*m_priv->stream << actualMsg;
	}

	return *this;
}
CharMessageBuffer& CharMessageBuffer::operator<<(char* msg)
{
	return operator<<((const char*) msg);
}

CharMessageBuffer& CharMessageBuffer::operator<<(const char msg)
{
	if (m_priv->stream == 0)
	{
		m_priv->buf.append(1, msg);
	}
	else
	{
		m_priv->buf.assign(1, msg);
		*m_priv->stream << m_priv->buf;
	}

	return *this;
}

CharMessageBuffer::operator std::basic_ostream<char>& ()
{
	return m_priv->StreamFromBuf();
}

std::basic_string<char> CharMessageBuffer::extract_str(std::basic_ostream<char>&)
{
	return std::move(m_priv->BufFromStream());
}

std::basic_string<char> CharMessageBuffer::extract_str(CharMessageBuffer&)
{
	return std::move(m_priv->BufFromStream());
}

const std::basic_string<char>& CharMessageBuffer::str(std::basic_ostream<char>&)
{
	return m_priv->BufFromStream();
}

const std::basic_string<char>& CharMessageBuffer::str(CharMessageBuffer&)
{
	return m_priv->BufFromStream();
}

bool CharMessageBuffer::hasStream() const
{
	return (m_priv->stream != 0);
}

std::ostream& CharMessageBuffer::operator<<(ios_base_manip manip)
{
	std::ostream& s = *this;
	(*manip)(s);
	return s;
}

std::ostream& CharMessageBuffer::operator<<(bool val)
{
	return ((std::ostream&) * this).operator << (val);
}
std::ostream& CharMessageBuffer::operator<<(short val)
{
	return ((std::ostream&) * this).operator << (val);
}
std::ostream& CharMessageBuffer::operator<<(int val)
{
	return ((std::ostream&) * this).operator << (val);
}
std::ostream& CharMessageBuffer::operator<<(unsigned int val)
{
	return ((std::ostream&) * this).operator << (val);
}
std::ostream& CharMessageBuffer::operator<<(long val)
{
	return ((std::ostream&) * this).operator << (val);
}
std::ostream& CharMessageBuffer::operator<<(unsigned long val)
{
	return ((std::ostream&) * this).operator << (val);
}
std::ostream& CharMessageBuffer::operator<<(float val)
{
	return ((std::ostream&) * this).operator << (val);
}
std::ostream& CharMessageBuffer::operator<<(double val)
{
	return ((std::ostream&) * this).operator << (val);
}
std::ostream& CharMessageBuffer::operator<<(long double val)
{
	return ((std::ostream&) * this).operator << (val);
}
std::ostream& CharMessageBuffer::operator<<(void* val)
{
	return ((std::ostream&) * this).operator << (val);
}

#if LOG4CXX_WCHAR_T_API
struct WideMessageBuffer::WideMessageBufferPrivate : public StringOrStream<wchar_t> {};

WideMessageBuffer::WideMessageBuffer() :
	m_priv(std::make_unique<WideMessageBufferPrivate>())
{
}

WideMessageBuffer::~WideMessageBuffer()
{
}

WideMessageBuffer& WideMessageBuffer::operator<<(const std::basic_string<wchar_t>& msg)
{
	if (m_priv->stream == 0)
	{
		m_priv->buf.append(msg);
	}
	else
	{
		*m_priv->stream << msg;
	}

	return *this;
}

WideMessageBuffer& WideMessageBuffer::operator<<(const wchar_t* msg)
{
	const wchar_t* actualMsg = msg;

	if (actualMsg == 0)
	{
		actualMsg = L"null";
	}

	if (m_priv->stream == 0)
	{
		m_priv->buf.append(actualMsg);
	}
	else
	{
		*m_priv->stream << actualMsg;
	}

	return *this;
}

WideMessageBuffer& WideMessageBuffer::operator<<(wchar_t* msg)
{
	return operator<<((const wchar_t*) msg);
}

WideMessageBuffer& WideMessageBuffer::operator<<(const wchar_t msg)
{
	if (m_priv->stream == 0)
	{
		m_priv->buf.append(1, msg);
	}
	else
	{
		m_priv->buf.assign(1, msg);
		*m_priv->stream << m_priv->buf;
	}

	return *this;
}

WideMessageBuffer::operator std::basic_ostream<wchar_t>& ()
{
	return m_priv->StreamFromBuf();
}

std::basic_string<wchar_t> WideMessageBuffer::extract_str(std::basic_ostream<wchar_t>&)
{
	return std::move(m_priv->BufFromStream());
}

std::basic_string<wchar_t> WideMessageBuffer::extract_str(WideMessageBuffer&)
{
	return std::move(m_priv->BufFromStream());
}

const std::basic_string<wchar_t>& WideMessageBuffer::str(std::basic_ostream<wchar_t>&)
{
	return m_priv->BufFromStream();
}

const std::basic_string<wchar_t>& WideMessageBuffer::str(WideMessageBuffer&)
{
	return m_priv->BufFromStream();
}

bool WideMessageBuffer::hasStream() const
{
	return (m_priv->stream != 0);
}

std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(ios_base_manip manip)
{
	std::basic_ostream<wchar_t>& s = *this;
	(*manip)(s);
	return s;
}

std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(bool val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}
std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(short val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}
std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(int val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}
std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(unsigned int val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}
std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(long val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}
std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(unsigned long val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}
std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(float val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}
std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(double val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}
std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(long double val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}
std::basic_ostream<wchar_t>& WideMessageBuffer::operator<<(void* val)
{
	return ((std::basic_ostream<wchar_t>&) * this).operator << (val);
}

struct MessageBuffer::MessageBufferPrivate{
	MessageBufferPrivate(){}

	/**
	 *  Character message buffer.
	 */
	CharMessageBuffer cbuf;

	/**
	 * Encapsulated wide message buffer, created on demand.
	 */
	std::unique_ptr<WideMessageBuffer> wbuf;
};

MessageBuffer::MessageBuffer()  :
	m_priv(std::make_unique<MessageBufferPrivate>())
{
}

MessageBuffer::~MessageBuffer()
{
}

bool MessageBuffer::hasStream() const
{
	bool retval = m_priv->cbuf.hasStream() || (m_priv->wbuf != 0 && m_priv->wbuf->hasStream());
	return retval;
}

std::ostream& MessageBuffer::operator<<(ios_base_manip manip)
{
	std::ostream& s = *this;
	(*manip)(s);
	return s;
}

MessageBuffer::operator std::ostream& ()
{
	return (std::ostream&) m_priv->cbuf;
}

CharMessageBuffer& MessageBuffer::operator<<(const std::string& msg)
{
	return m_priv->cbuf.operator << (msg);
}

CharMessageBuffer& MessageBuffer::operator<<(const char* msg)
{
	return m_priv->cbuf.operator << (msg);
}
CharMessageBuffer& MessageBuffer::operator<<(char* msg)
{
	return m_priv->cbuf.operator << ((const char*) msg);
}

CharMessageBuffer& MessageBuffer::operator<<(const char msg)
{
	return m_priv->cbuf.operator << (msg);
}

std::string MessageBuffer::extract_str(CharMessageBuffer& buf)
{
	return std::move(m_priv->cbuf.extract_str(buf));
}

std::string MessageBuffer::extract_str(std::ostream& os)
{
	return std::move(m_priv->cbuf.extract_str(os));
}

const std::string& MessageBuffer::str(CharMessageBuffer& buf)
{
	return m_priv->cbuf.str(buf);
}

const std::string& MessageBuffer::str(std::ostream& os)
{
	return m_priv->cbuf.str(os);
}

WideMessageBuffer& MessageBuffer::operator<<(const std::wstring& msg)
{
	m_priv->wbuf = std::make_unique<WideMessageBuffer>();
	return (*m_priv->wbuf) << msg;
}

WideMessageBuffer& MessageBuffer::operator<<(const wchar_t* msg)
{
	m_priv->wbuf = std::make_unique<WideMessageBuffer>();
	return (*m_priv->wbuf) << msg;
}
WideMessageBuffer& MessageBuffer::operator<<(wchar_t* msg)
{
	m_priv->wbuf = std::make_unique<WideMessageBuffer>();
	return (*m_priv->wbuf) << (const wchar_t*) msg;
}

WideMessageBuffer& MessageBuffer::operator<<(const wchar_t msg)
{
	m_priv->wbuf = std::make_unique<WideMessageBuffer>();
	return (*m_priv->wbuf) << msg;
}

std::wstring MessageBuffer::extract_str(WideMessageBuffer& buf)
{
	return std::move(m_priv->wbuf->extract_str(buf));
}

std::wstring MessageBuffer::extract_str(std::basic_ostream<wchar_t>& os)
{
	return std::move(m_priv->wbuf->extract_str(os));
}

const std::wstring& MessageBuffer::str(WideMessageBuffer& buf)
{
	return m_priv->wbuf->str(buf);
}

const std::wstring& MessageBuffer::str(std::basic_ostream<wchar_t>& os)
{
	return m_priv->wbuf->str(os);
}

std::ostream& MessageBuffer::operator<<(bool val)
{
	return m_priv->cbuf.operator << (val);
}
std::ostream& MessageBuffer::operator<<(short val)
{
	return m_priv->cbuf.operator << (val);
}
std::ostream& MessageBuffer::operator<<(int val)
{
	return m_priv->cbuf.operator << (val);
}
std::ostream& MessageBuffer::operator<<(unsigned int val)
{
	return m_priv->cbuf.operator << (val);
}
std::ostream& MessageBuffer::operator<<(long val)
{
	return m_priv->cbuf.operator << (val);
}
std::ostream& MessageBuffer::operator<<(unsigned long val)
{
	return m_priv->cbuf.operator << (val);
}
std::ostream& MessageBuffer::operator<<(float val)
{
	return m_priv->cbuf.operator << (val);
}
std::ostream& MessageBuffer::operator<<(double val)
{
	return m_priv->cbuf.operator << (val);
}
std::ostream& MessageBuffer::operator<<(long double val)
{
	return m_priv->cbuf.operator << (val);
}
std::ostream& MessageBuffer::operator<<(void* val)
{
	return m_priv->cbuf.operator << (val);
}


#endif // LOG4CXX_WCHAR_T_API

#if LOG4CXX_CFSTRING_API
#include <CoreFoundation/CFString.h>
#include <vector>

CharMessageBuffer& CharMessageBuffer::operator<<(const CFStringRef& msg)
{
	LOG4CXX_DECODE_CFSTRING(tmp, msg);
	if (m_priv->stream)
	{
		*m_priv->stream << tmp;
	}
	else
	{
		m_priv->buf.append(tmp);
	}
	return *this;
}

#if LOG4CXX_WCHAR_T_API
CharMessageBuffer& MessageBuffer::operator<<(const CFStringRef& msg)
{
	LOG4CXX_DECODE_CFSTRING(tmp, msg);
	return m_priv->cbuf << tmp;
}
#endif // LOG4CXX_WCHAR_T_API

#endif // LOG4CXX_CFSTRING_API

