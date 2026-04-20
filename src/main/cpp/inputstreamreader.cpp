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

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/inputstreamreader.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(InputStreamReader)

struct InputStreamReader::InputStreamReaderPrivate{
	InputStreamReaderPrivate(const InputStreamPtr& in1) :
		in(in1), dec(CharsetDecoder::getDefaultDecoder()){}

	InputStreamReaderPrivate(const InputStreamPtr& in1, const CharsetDecoderPtr& dec1) :
		in(in1), dec(dec1) {}

	InputStreamPtr in;
	CharsetDecoderPtr dec;
};

InputStreamReader::InputStreamReader(const InputStreamPtr& in1)
	: m_priv(std::make_unique<InputStreamReaderPrivate>(in1))
{
	if (!in1)
	{
		throw NullPointerException(LOG4CXX_STR("InputStream parameter"));
	}
}

InputStreamReader::InputStreamReader(const InputStreamPtr& in1, const CharsetDecoderPtr& dec1)
	: m_priv(std::make_unique<InputStreamReaderPrivate>(in1, dec1))
{
	if (!in1)
	{
		throw NullPointerException(LOG4CXX_STR("InputStream parameter"));
	}

	if (!dec1)
	{
		throw NullPointerException(LOG4CXX_STR("CharsetDecoder parameter"));
	}
}

InputStreamReader::~InputStreamReader()
{
}

void InputStreamReader::close(Pool& )
{
	m_priv->in->close();
}

LogString InputStreamReader::read(Pool& p)
{
	const size_t BUFSIZE = 4096;
	ByteBuffer buf(p.pstralloc(BUFSIZE), BUFSIZE);
	LogString output;
	log4cxx_status_t stat{ 0 };

	// read whole file
	while (m_priv->in->read(buf) >= 0)
	{
		buf.flip();
		auto lastAvailableCount = buf.remaining();
		stat = m_priv->dec->decode(buf, output);
		if (buf.remaining() == lastAvailableCount)
		{
			if (stat == 0)
				stat = -1;
			break;
		}
		buf.carry();
	}
	if (stat != 0 && 0 < buf.remaining())
	{
		auto toHexDigit = [](int ch) -> int
		{
			return (10 <= ch ? (0x61 - 10) : 0x30) + ch;
		};
		LogString msg(LOG4CXX_STR("Unable to decode character 0x"));
		auto ch = static_cast<unsigned int>(*buf.current());
		msg.push_back(toHexDigit((ch & 0xF0) >> 4));
		msg.push_back(toHexDigit((ch & 0xF)));
		msg += LOG4CXX_STR(" at offset ");
		StringHelper::toString(output.size(), msg);
		throw RuntimeException(msg);
	}

	return output;
}
