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

#ifndef _LOG4CXX_HELPERS_FILEOUTPUTSTREAM_H
#define _LOG4CXX_HELPERS_FILEOUTPUTSTREAM_H

#include <log4cxx/helpers/outputstream.h>
#include <log4cxx/file.h>


namespace LOG4CXX_NS
{

namespace helpers
{

/**
*   OutputStream implemented on top of APR file IO.
*/
class LOG4CXX_EXPORT FileOutputStream : public OutputStream
{
	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(FileOutputStreamPrivate, m_priv)

	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(FileOutputStream)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(FileOutputStream)
		LOG4CXX_CAST_ENTRY_CHAIN(OutputStream)
		END_LOG4CXX_CAST_MAP()

		FileOutputStream(const LogString& filename, bool append = false);
		FileOutputStream(const logchar* filename, bool append = false);
		virtual ~FileOutputStream();

		void close(Pool& p) override;
		void flush(Pool& p) override;
		void write(ByteBuffer& buf, Pool& p) override;

		apr_file_t* getFilePtr() const;

	private:
		FileOutputStream(const FileOutputStream&) = delete;
		FileOutputStream(FileOutputStream&&) = delete;
		FileOutputStream& operator=(const FileOutputStream&) = delete;
		static apr_file_t* open(const LogString& fn, bool append,
			LOG4CXX_NS::helpers::Pool& p);
};

LOG4CXX_PTR_DEF(FileOutputStream);
} // namespace helpers

}  //namespace log4cxx

#endif //_LOG4CXX_HELPERS_FILEOUTPUTSTREAM_H
