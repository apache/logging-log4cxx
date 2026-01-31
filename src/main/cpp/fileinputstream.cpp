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
#include <log4cxx/helpers/fileinputstream.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/pool.h>
#include <fstream>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct FileInputStream::FileInputStreamPrivate
{
    FileInputStreamPrivate(){}

    std::fstream m_fstream;
};

IMPLEMENT_LOG4CXX_OBJECT(FileInputStream)

FileInputStream::FileInputStream(const LogString& filename) :
	m_priv(std::make_unique<FileInputStreamPrivate>())
{
	open(filename);
}

FileInputStream::FileInputStream(const logchar* filename) :
	m_priv(std::make_unique<FileInputStreamPrivate>())
{
	LogString fn(filename);
	open(fn);
}


void FileInputStream::open(const LogString& filename)
{

    bool success = File().setPath(filename).open(&m_priv->m_fstream, 0, 0);

    if (!success)
	{
        throw IOException(filename);
	}
}


FileInputStream::FileInputStream(const File& aFile) :
	m_priv(std::make_unique<FileInputStreamPrivate>())
{
    bool success = File().setPath(aFile.getName()).open(&m_priv->m_fstream, 0, 0);

    if (!success)
    {
        throw IOException(aFile.getName());
    }
}


FileInputStream::~FileInputStream()
{
    close();
}


void FileInputStream::close()
{
    if (m_priv->m_fstream.is_open())
    {
        m_priv->m_fstream.close();
    }
}


int FileInputStream::read(ByteBuffer& buf)
{
    size_t bytesRead = buf.remaining();
    size_t before_read = m_priv->m_fstream.tellg();
    m_priv->m_fstream.read(buf.current(), bytesRead);
    size_t after_read = m_priv->m_fstream.tellg();
	int retval = -1;

    if (!m_priv->m_fstream.eof())
    {
		buf.position(buf.position() + bytesRead);
        retval = (int)(after_read - before_read);
	}

	return retval;
}
