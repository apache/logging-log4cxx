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
#include <log4cxx/file.h>
#include <apr_file_io.h>
#include <apr_file_info.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/pool.h>
#include <assert.h>
#include <log4cxx/helpers/exception.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct File::FilePrivate{
	FilePrivate()
	{}

	FilePrivate(const LogString& path)
		: path(path)
	{}

	FilePrivate(const LogString& path, bool autoDelete)
		: path(path)
		, autoDelete(autoDelete)
	{}

	LogString path;
	bool autoDelete{ false };
	Pool p;
	char* apr_path{ nullptr };
	char* getPath();
	static char* convertBackSlashes(char*);
};

File::File() :
	m_priv(std::make_unique<FilePrivate>())
{
}

template<class S>
static LogString decodeLS(const S* src)
{
	LogString dst;

	if (src != 0)
	{
		Transcoder::decode(src, dst);
	}

	return dst;
}

template<class S>
static LogString decodeLS(const std::basic_string<S>& src)
{
	LogString dst;
	Transcoder::decode(src, dst);
	return dst;
}


File::File(const std::string& name1)
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name1)))
{
}

File::File(const char* name1)
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name1)))
{
}

#if LOG4CXX_WCHAR_T_API
File::File(const std::wstring& name1)
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name1)))
{
}

File::File(const wchar_t* name1)
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name1)))
{
}
#endif

#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
File::File(const std::basic_string<UniChar>& name1)
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name1)))
{
}

File::File(const UniChar* name1)
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name1)))
{
}
#endif

#if LOG4CXX_CFSTRING_API
File::File(const CFStringRef& name1)
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name1)))
{
}
#endif

File::File(const File& src)
	: m_priv(std::make_unique<FilePrivate>(src.m_priv->path, src.m_priv->autoDelete))
{
}

File& File::operator=(const File& src)
{
	if (this == &src)
	{
		return *this;
	}

	m_priv->path.assign(src.m_priv->path);
	m_priv->autoDelete = src.m_priv->autoDelete;

	return *this;
}


File::~File()
{
	if(m_priv->autoDelete){
		deleteFile();
	}
}


LogString File::getPath() const
{
	return m_priv->path;
}

File& File::setPath(const LogString& newName)
{
	m_priv->path.assign(newName);
	m_priv->apr_path = nullptr;
	return *this;
}

LogString File::getName() const
{
	const logchar slashes[] = { 0x2F, 0x5C, 0 };
	size_t lastSlash = m_priv->path.find_last_of(slashes);

	if (lastSlash != LogString::npos)
	{
		return m_priv->path.substr(lastSlash + 1);
	}

	return m_priv->path;
}

char* File::FilePrivate::getPath()
{
	if (this->apr_path)
		return this->apr_path;
	int style = APR_FILEPATH_ENCODING_UNKNOWN;
	apr_filepath_encoding(&style, this->p.getAPRPool());

	if (style == APR_FILEPATH_ENCODING_UTF8)
	{
		this->apr_path = Transcoder::encodeUTF8(this->path, this->p);
	}
	else
	{
		this->apr_path = Transcoder::encode(this->path, this->p);
	}

	return convertBackSlashes(this->apr_path);
}

const char* File::getAPRPath() const
{
	return m_priv->getPath();
}

#if LOG4CXX_ABI_VERSION <= 15
log4cxx_status_t File::open(apr_file_t** file, int flags, int perm, helpers::Pool& p) const
{
	return apr_file_open(file, m_priv->getPath(), flags, perm, p.getAPRPool());
}
#endif

bool File::exists() const
{
	apr_finfo_t finfo;
	apr_status_t rv = apr_stat(&finfo, m_priv->getPath(), 0, m_priv->p.getAPRPool());
	return rv == APR_SUCCESS;
}

char* File::FilePrivate::convertBackSlashes(char* src)
{
	for (char* c = src; *c != 0; c++)
	{
		if (*c == '\\')
		{
			*c = '/';
		}
	}

	return src;
}

bool File::deleteFile() const
{
	apr_status_t rv = apr_file_remove(m_priv->getPath(), m_priv->p.getAPRPool());
	return rv == APR_SUCCESS;
}

bool File::renameTo(const File& dest) const
{
	apr_status_t rv = apr_file_rename(m_priv->getPath(), dest.m_priv->getPath(), m_priv->p.getAPRPool());
	return rv == APR_SUCCESS;
}


size_t File::length() const
{
	apr_finfo_t finfo;
	apr_status_t rv = apr_stat(&finfo, m_priv->getPath(), APR_FINFO_SIZE, m_priv->p.getAPRPool());

	if (rv == APR_SUCCESS)
	{
		return (size_t) finfo.size;
	}

	return 0;
}


log4cxx_time_t File::lastModified() const
{
	apr_finfo_t finfo;
	apr_status_t rv = apr_stat(&finfo, m_priv->getPath(), APR_FINFO_MTIME, m_priv->p.getAPRPool());

	if (rv == APR_SUCCESS)
	{
		return finfo.mtime;
	}

	return 0;
}


std::vector<LogString> File::list() const
{
	apr_dir_t* dir;
	apr_finfo_t entry;
	std::vector<LogString> filenames;

	apr_status_t stat = apr_dir_open(&dir, m_priv->getPath(), m_priv->p.getAPRPool());

	if (stat == APR_SUCCESS)
	{
		int style = APR_FILEPATH_ENCODING_UNKNOWN;
		apr_filepath_encoding(&style, m_priv->p.getAPRPool());
		stat = apr_dir_read(&entry, APR_FINFO_DIRENT, dir);

		while (stat == APR_SUCCESS)
		{
			if (entry.name != NULL)
			{
				LogString filename;

				if (style == APR_FILEPATH_ENCODING_UTF8)
				{
					Transcoder::decodeUTF8(entry.name, filename);
				}
				else
				{
					Transcoder::decode(entry.name, filename);
				}

				filenames.push_back(filename);
			}

			stat = apr_dir_read(&entry, APR_FINFO_DIRENT, dir);
		}

		stat = apr_dir_close(dir);
	}

	return filenames;
}

LogString File::getParent() const
{
	LogString::size_type slashPos = m_priv->path.rfind(LOG4CXX_STR('/'));
	LogString::size_type backPos = m_priv->path.rfind(LOG4CXX_STR('\\'));

	if (slashPos == LogString::npos)
	{
		slashPos = backPos;
	}
	else
	{
		if (backPos != LogString::npos && backPos > slashPos)
		{
			slashPos = backPos;
		}
	}

	LogString parent;

	if (slashPos != LogString::npos && slashPos > 0)
	{
		parent.assign(m_priv->path, 0, slashPos);
	}

	return parent;
}

bool File::mkdirs() const
{
	apr_status_t stat = apr_dir_make_recursive(m_priv->getPath(), APR_OS_DEFAULT, m_priv->p.getAPRPool());
	return stat == APR_SUCCESS;
}

void File::setAutoDelete(bool autoDelete){
	m_priv->autoDelete = autoDelete;
}

bool File::getAutoDelete() const{
	return m_priv->autoDelete;
}

#if LOG4CXX_ABI_VERSION <= 15
bool File::exists(helpers::Pool& p) const { return exists(); }
size_t File::length(helpers::Pool& p) const { return length(); }
log4cxx_time_t File::lastModified(helpers::Pool& p) const { return lastModified(); }
std::vector<LogString> File::list(helpers::Pool& p) const { return list(); }
bool File::deleteFile(helpers::Pool& p) const { return deleteFile(); }
bool File::renameTo(const File& dest, helpers::Pool& p) const { return renameTo(dest); }
LogString File::getParent(helpers::Pool& p) const { return getParent(); }
bool File::mkdirs(helpers::Pool& p) const { return mkdirs(); }
#endif
