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
#include <cstring> // memmove

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct LOG4CXX_NS::helpers::ByteBufferPriv
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

void ByteBufferPriv::clear()
{
	this->lim = this->cap;
	this->pos = 0;
}

void ByteBufferPriv::carry()
{
	auto available = remaining();
	memmove(this->base, current(), available);
	this->lim = this->cap;
	this->pos = available;
}

void ByteBufferPriv::flip()
{
	this->lim = this->pos;
	this->pos = 0;
}

bool ByteBufferPriv::put(char byte)
{
	if (this->pos < this->lim)
	{
		this->base[this->pos++] = byte;
		return true;
	}

	return false;
}

char* ByteBufferPriv::data()
{
	return this->base;
}

const char* ByteBufferPriv::data() const
{
	return this->base;
}

char* ByteBufferPriv::current()
{
	return this->base + this->pos;
}

const char* ByteBufferPriv::current() const
{
	return this->base + this->pos;
}

size_t ByteBufferPriv::limit() const
{
	return this->lim;
}

size_t ByteBufferPriv::position() const
{
	return this->pos;
}

size_t ByteBufferPriv::remaining() const
{
	return this->lim - this->pos;
}

size_t ByteBufferPriv::increment_position(size_t byteCount)
{
    auto available = remaining();
    this->pos += byteCount < available ? byteCount : available;
    return remaining();
}
