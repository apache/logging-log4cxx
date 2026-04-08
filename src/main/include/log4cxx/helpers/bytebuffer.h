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

#ifndef _LOG4CXX_HELPERS_BYTEBUFFER_H
#define _LOG4CXX_HELPERS_BYTEBUFFER_H

#include <log4cxx/log4cxx.h>
#include <stdio.h>

namespace LOG4CXX_NS
{

namespace helpers
{

/**
* An area of memory and a cursor into that memory.
* <p>Provides the remaining bytes available for storage or to be processed.
* <p>The \c flip method switches its role from being a space for storage
* to being a collection of bytes to be processed.
* <p>The \c carry method switches it back to being a space for storage,
* while retaining any unprocessed bytes.
* <p>It does not own the memory, so does not allocate or free memory.
* The user must ensure the lifetime of the memory exceeds the lifeime of the class instance.
*/
class LOG4CXX_EXPORT ByteBuffer
{
	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(ByteBufferPriv, m_priv)

	public:
		/// A \c capacity sized area of memory at \c data.
		ByteBuffer(char* data, size_t capacity);
		~ByteBuffer();

		/// Move the remaining bytes to the start of the memory area
		/// and set the cursor to the end of the those bytes.
		void carry();

		/// Set the cursor to the start of the memory area
		/// and use the capacity as the extent to which the cursor can advance.
		void clear();

		/// Set the extent to which the cursor can advance, \c limit(), to the current cursor position
		/// and move the cursor to the start of the memory area.
		void flip();

		/// The start of the memory area.
		char* data();
		/// The start of the memory area.
		const char* data() const;

		/// The memory at the cursor position.
		char* current();
		/// The memory at the cursor position.
		const char* current() const;

		/// The extent to which the cursor can advance
		/// as an offset from the start of the memory area.
		/// Intially this is the capacity of the buffer.
		size_t limit() const;

#if LOG4CXX_ABI_VERSION <= 15
		/// Use \c newLimit as the extent to which the cursor can advance.
		/// If \c newLimit exceeds the memory capacity, an exception is thrown.
		/// If the current cursor is currently beyond \c newLimit
		/// the cursor is changed to be at \c newLimit.
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Use flip instead" ) ]]
		void limit(size_t newLimit);
#endif

		/// The offset of the current cursor from the start of the memory area.
		size_t position() const;

		/// The number of bytes from the current cursor
		/// until the cursor can no longer advance.
		size_t remaining() const;

#if LOG4CXX_ABI_VERSION <= 15
		/// Use \c newPosition as the cursor position
		/// providing it is less than the extent to which the cursor can advance,
		/// otherwise set the cursor to the extent to which the cursor can advance.
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Use increment_position instead" ) ]]
		void position(size_t newPosition);
#endif
		/// Advance the cursor by \c byteCount
		/// if that does not exceed the extent to which the cursor can advance,
		/// otherwise set the cursor to the extent to which the cursor can advance.
		/// @returns The number of bytes until the cursor can no longer advance.
		size_t increment_position(size_t byteCount);

		/// Store \c byteValue at the cursor position and advance the cursor position
		/// unless the cursor cannot advance any further.
		/// @returns true if \c byteValue was stored in the buffer.
		bool put(char byteValue);


	private:
		ByteBuffer(const ByteBuffer&);
		ByteBuffer& operator=(const ByteBuffer&);
};
} // namespace helpers

}  //namespace log4cxx

#endif //_LOG4CXX_HELPERS_BYTEBUFFER_H
