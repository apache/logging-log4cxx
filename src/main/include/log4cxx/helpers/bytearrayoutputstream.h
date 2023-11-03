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

#ifndef _LOG4CXX_HELPERS_BYTEARRAYOUTPUTSTREAM_H
#define _LOG4CXX_HELPERS_BYTEARRAYOUTPUTSTREAM_H

#include <log4cxx/helpers/outputstream.h>
#include <vector>

namespace LOG4CXX_NS
{

namespace helpers
{
class Pool;

LOG4CXX_LIST_DEF(ByteList, unsigned char);

/**
*   OutputStream implemented on top of std::vector
*/
class LOG4CXX_EXPORT ByteArrayOutputStream : public OutputStream
{
	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(ByteArrayOutputStreamPriv, m_priv)

	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(ByteArrayOutputStream)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(ByteArrayOutputStream)
		LOG4CXX_CAST_ENTRY_CHAIN(OutputStream)
		END_LOG4CXX_CAST_MAP()

		ByteArrayOutputStream();
		virtual ~ByteArrayOutputStream();

		void close(Pool& p) override;
		void flush(Pool& p) override;
		void write(ByteBuffer& buf, Pool& p) override;
		ByteList toByteArray() const;

	private:
		ByteArrayOutputStream(const ByteArrayOutputStream&);
		ByteArrayOutputStream& operator=(const ByteArrayOutputStream&);
};

LOG4CXX_PTR_DEF(ByteArrayOutputStream);
} // namespace helpers

}  //namespace log4cxx

#endif //_LOG4CXX_HELPERS_BYTEARRAYOUTPUTSTREAM_H
