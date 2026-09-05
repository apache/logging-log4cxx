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
#include <log4cxx/private/bytebuffer_priv.h>
#if LOG4CXX_ABI_VERSION <= 15
#include <log4cxx/helpers/exception.h>
#endif
#include <cstring>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

ByteBuffer::ByteBuffer(char* data1, size_t capacity)
	: m_priv(std::make_unique<ByteBufferPriv>(data1, capacity))
{
}

ByteBuffer::~ByteBuffer()
{
}

ByteBufferPriv& ByteBuffer::impl()
{
    return *m_priv;
}

void ByteBuffer::clear()
{
	m_priv->clear();
}

void ByteBuffer::carry()
{
	m_priv->carry();
}

void ByteBuffer::flip()
{
	m_priv->flip();
}

#if LOG4CXX_ABI_VERSION <= 15
void ByteBuffer::position(size_t newPosition)
{
	if (newPosition < m_priv->lim)
	{
		m_priv->pos = newPosition;
	}
	else
	{
		m_priv->pos = m_priv->lim;
	}
}

void ByteBuffer::limit(size_t newLimit)
{
	if (newLimit > m_priv->cap)
	{
		throw IllegalArgumentException(LOG4CXX_STR("newLimit"));
	}

	m_priv->lim = newLimit;

	if (m_priv->pos > m_priv->lim)
	{
		m_priv->pos = m_priv->lim;
	}
}
#endif

bool ByteBuffer::put(char byte)
{
	return m_priv->put(byte);
}

char* ByteBuffer::data()
{
	return m_priv->data();
}

const char* ByteBuffer::data() const
{
	return m_priv->data();
}

char* ByteBuffer::current()
{
	return m_priv->current();
}

const char* ByteBuffer::current() const
{
	return m_priv->current();
}

size_t ByteBuffer::limit() const
{
	return m_priv->limit();
}

size_t ByteBuffer::position() const
{
	return m_priv->position();
}

size_t ByteBuffer::remaining() const
{
	return m_priv->remaining();
}

size_t ByteBuffer::increment_position(size_t byteCount)
{
    return m_priv->increment_position(byteCount);
}
