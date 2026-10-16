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
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <apr_file_io.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct FileOutputStream::FileOutputStreamPrivate
{
	FileOutputStreamPrivate(const LogString& filename, bool append)
		: path(filename), logAppend(append)
		{}

	File path;
	Pool pool;
	apr_file_t* fileptr{ nullptr };
	bool logAppend;
	void open();
	void openUnlessLazy(bool lazyOpen);
};

IMPLEMENT_LOG4CXX_OBJECT(FileOutputStream)

FileOutputStream::FileOutputStream(const LogString& filename, bool append, bool lazyOpen)
	: m_priv(std::make_unique<FileOutputStreamPrivate>(filename, append))
{
	m_priv->openUnlessLazy(lazyOpen);
}

void FileOutputStream::FileOutputStreamPrivate::openUnlessLazy(bool lazyOpen)
{
	if (!lazyOpen)
	{
		this->open();
	}
	else if (!this->logAppend && this->path.exists())
	{
		// Truncate the file (i.e. remove its contents)
		this->open();
	}
}

void FileOutputStream::FileOutputStreamPrivate::open()
{
	apr_fileperms_t perm = APR_OS_DEFAULT;
	apr_int32_t flags = APR_WRITE | APR_CREATE;

	if (this->logAppend)
	{
		flags |= APR_APPEND;
	}
	else
	{
		flags |= APR_TRUNCATE;
	}

	apr_status_t stat = apr_file_open(&this->fileptr, this->path.getAPRPath(), flags, perm, this->pool.getAPRPool());

	if (stat != APR_SUCCESS)
	{
		throw IOException(this->path.getAPRPath(), stat);
	}
}

FileOutputStream::~FileOutputStream()
{
	if (m_priv->fileptr)
	{
		apr_file_close(m_priv->fileptr);
		m_priv->fileptr = nullptr;
	}
}

void FileOutputStream::close(  )
{
	if (m_priv->fileptr)
	{
		apr_status_t stat = apr_file_close(m_priv->fileptr);

		if (stat != APR_SUCCESS)
		{
			throw IOException(stat);
		}

		m_priv->fileptr = NULL;
	}
}

void FileOutputStream::flush(  )
{
}

void FileOutputStream::write( ByteBuffer& buf )
{
	if (m_priv->fileptr == NULL)
	{
		m_priv->open();

		if (m_priv->fileptr == nullptr)
		{
			throw NullPointerException(LOG4CXX_STR("FileOutputStream"));
		}
	}

	size_t nbytes = buf.remaining();
	while (nbytes > 0)
	{
		apr_status_t stat = apr_file_write(
				m_priv->fileptr, buf.current(), &nbytes);

		if (stat != APR_SUCCESS)
		{
			throw IOException(stat);
		}

		nbytes = buf.increment_position(nbytes);
	}
}

apr_file_t* FileOutputStream::getFilePtr() const{
	if (!m_priv->fileptr)
	{
		try
		{
			m_priv->open();
		}
		catch (IOException&)
		{
			// write() will open (and report any failure) again
		}
	}
	return m_priv->fileptr;
}

