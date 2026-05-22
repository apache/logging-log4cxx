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
#include <log4cxx/helpers/bytearrayoutputstream.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/bytebuffer.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct ByteArrayOutputStream::ByteArrayOutputStreamPriv
{
	ByteList array;
};

IMPLEMENT_LOG4CXX_OBJECT(ByteArrayOutputStream)

ByteArrayOutputStream::ByteArrayOutputStream()
	: m_priv(std::make_unique<ByteArrayOutputStreamPriv>())
{
}

ByteArrayOutputStream::~ByteArrayOutputStream()
{
}

void ByteArrayOutputStream::close( LOG4CXX_CLOSE_OUTPUT_STREAM_FORMAL_PARAMETERS )
{
}

void ByteArrayOutputStream::flush( LOG4CXX_FLUSH_OUTPUT_STREAM_FORMAL_PARAMETERS )
{
}

void ByteArrayOutputStream::write( LOG4CXX_WRITE_OUTPUT_STREAM_FORMAL_PARAMETERS )
{
	const size_t count = buf.remaining();

	if (count == 0)
	{
		return;
	}

	if (count > m_priv->array.max_size() - m_priv->array.size())
	{
		throw IllegalArgumentException(LOG4CXX_STR("ByteArrayOutputStream::write overflow"));
	}

	const char* const current = buf.current();
	m_priv->array.insert(m_priv->array.end(), current, current + count);
	buf.increment_position(count);
}

std::vector<unsigned char> ByteArrayOutputStream::toByteArray() const
{
	return m_priv->array;
}


