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
#include <log4cxx/helpers/bytebuffer.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct ByteBuffer::ByteBufferPriv
{
private: // Attributes
	char* base;
	size_t pos;
	size_t lim;
	size_t cap;

public: // ...structor
	ByteBufferPriv(char* data, size_t capacity)
		: base(data)
		, pos(0)
		, lim(capacity)
		, cap(capacity)
		{}

public: // Accessors
	inline char* data();
	inline const char* data() const;
	inline char* current();
	inline const char* current() const;
	inline size_t limit() const;
	inline size_t position() const;
	inline size_t remaining() const;

public: // Modifiers
	inline void carry();
	inline void clear();
	inline void flip();
	inline size_t increment_position(size_t byteCount);
	inline bool put(char byteValue);

#if LOG4CXX_ABI_VERSION <= 15
	friend class ByteBuffer;
#endif
};

void ByteBuffer::ByteBufferPriv::clear()
{
	this->lim = this->cap;
	this->pos = 0;
}

void ByteBuffer::ByteBufferPriv::carry()
{
	auto available = remaining();
	memmove(this->base, current(), available);
	this->lim = this->cap;
	this->pos = available;
}

void ByteBuffer::ByteBufferPriv::flip()
{
	this->lim = this->pos;
	this->pos = 0;
}

bool ByteBuffer::ByteBufferPriv::put(char byte)
{
	if (this->pos < this->lim)
	{
		this->base[this->pos++] = byte;
		return true;
	}

	return false;
}

char* ByteBuffer::ByteBufferPriv::data()
{
	return this->base;
}

const char* ByteBuffer::ByteBufferPriv::data() const
{
	return this->base;
}

char* ByteBuffer::ByteBufferPriv::current()
{
	return this->base + this->pos;
}

const char* ByteBuffer::ByteBufferPriv::current() const
{
	return this->base + this->pos;
}

size_t ByteBuffer::ByteBufferPriv::limit() const
{
	return this->lim;
}

size_t ByteBuffer::ByteBufferPriv::position() const
{
	return this->pos;
}

size_t ByteBuffer::ByteBufferPriv::remaining() const
{
	return this->lim - this->pos;
}

size_t ByteBuffer::ByteBufferPriv::increment_position(size_t byteCount)
{
    auto available = remaining();
    this->pos += byteCount < available ? byteCount : available;
    return remaining();
}
