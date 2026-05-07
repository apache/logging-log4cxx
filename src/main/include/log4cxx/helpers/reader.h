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

#ifndef _LOG4CXX_HELPERS_READER_H
#define _LOG4CXX_HELPERS_READER_H

#include <log4cxx/helpers/object.h>

namespace LOG4CXX_NS
{

namespace helpers
{

/**
 * Abstract class for reading from character streams.
 *
 */
class LOG4CXX_EXPORT Reader : public Object
{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Reader)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(Reader)
		END_LOG4CXX_CAST_MAP()

	protected:
		/**
		 * Creates a new character-stream reader.
		 */
		Reader();

		virtual ~Reader();

	public:
#if LOG4CXX_ABI_VERSION <= 15
		/**
		 * Closes the stream.
		 */
		void close();

		/**
		 * @return The complete stream contents as a LogString.
		 */
		LogString read();

		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to close() without a helpers::Pool parameter.
		*/
		virtual void close(Pool& p) = 0;
#define LOG4CXX_CLOSE_READER_FORMAL_PARAMETERS helpers::Pool& p
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to close() without a helpers::Pool parameter.
		*/
		virtual LogString read(Pool& p) = 0;
#define LOG4CXX_READ_READER_FORMAL_PARAMETERS helpers::Pool& p
#else
		/**
		 * Closes the stream.
		 */
		virtual void close() = 0;
#define LOG4CXX_CLOSE_READER_FORMAL_PARAMETERS

		/**
		 * @return The complete stream contents as a LogString.
		 */
		virtual LogString read() = 0;
#define LOG4CXX_READ_READER_FORMAL_PARAMETERS
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		[[deprecated("Use close() without a Pool parameter instead")]]
		void close(Pool& p);
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		[[deprecated("Use read() without a Pool parameter instead")]]
		LogString read(Pool& p);
#endif

	private:
		Reader(const Reader&);

		Reader& operator=(const Reader&);
};

LOG4CXX_PTR_DEF(Reader);
} // namespace helpers

}  //namespace log4cxx

#endif //_LOG4CXX_HELPERS_READER_H
