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

#ifndef _LOG4CXX_HELPERS_WRITER_H
#define _LOG4CXX_HELPERS_WRITER_H

#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/outputstream.h>

namespace LOG4CXX_NS
{

namespace helpers
{

/**
*   Abstract class for writing to character streams.
*/
class LOG4CXX_EXPORT Writer : public Object
{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Writer)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(Writer)
		END_LOG4CXX_CAST_MAP()

	protected:
		Writer();
		virtual ~Writer();

	public:
#if LOG4CXX_ABI_VERSION <= 15
		void close();
		void flush();
		void write(const LogString& str);
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to close() without a helpers::Pool parameter.
		*/
		virtual void close(Pool& p) = 0;
#define LOG4CXX_CLOSE_WRITER_FORMAL_PARAMETERS helpers::Pool& p
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to flush() without a helpers::Pool parameter.
		*/
		virtual void flush(Pool& p) = 0;
#define LOG4CXX_FLUSH_WRITER_FORMAL_PARAMETERS helpers::Pool& p
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to write() without a helpers::Pool parameter.
		*/
		virtual void write(const LogString& str, Pool& p) = 0;
#define LOG4CXX_WRITE_WRITER_FORMAL_PARAMETERS const LogString& str, helpers::Pool& p
#else
		virtual void close() = 0;
#define LOG4CXX_CLOSE_WRITER_FORMAL_PARAMETERS
		virtual void flush() = 0;
#define LOG4CXX_FLUSH_WRITER_FORMAL_PARAMETERS
		virtual void write(const LogString& str) = 0;
#define LOG4CXX_WRITE_WRITER_FORMAL_PARAMETERS const LogString& str
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		void close(Pool& p);
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		void flush(Pool& p);
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		void write(const LogString& str, Pool& p);
#endif
	private:
		Writer(const Writer&);
		Writer& operator=(const Writer&);
};

LOG4CXX_PTR_DEF(Writer);
} // namespace helpers

}  //namespace log4cxx

#endif //_LOG4CXX_HELPERS_WRITER_H
