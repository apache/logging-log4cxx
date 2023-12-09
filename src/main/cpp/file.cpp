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

#include <log4cxx/file.h>
#include <apr_file_io.h>
#include <apr_file_info.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/pool.h>

namespace LOG4CXX_NS
{

template<class S>
static LogString decodeLS(const S* src)
{
	LogString dst;

	if (src != 0)
	{
		helpers::Transcoder::decode(src, dst);
	}

	return dst;
}

template<class S>
static LogString decodeLS(const std::basic_string<S>& src)
{
	LogString dst;
	helpers::Transcoder::decode(src, dst);
	return dst;
}

char* getPath(helpers::Pool& p, const File& f)
{
	int style = APR_FILEPATH_ENCODING_UNKNOWN;
	apr_filepath_encoding(&style, p.getAPRPool());
	char* retval = NULL;

	if (style == APR_FILEPATH_ENCODING_UTF8)
	{
		retval = helpers::Transcoder::encodeUTF8(getPath(f), p);
	}
	else
	{
		retval = helpers::Transcoder::encode(getPath(f), p);
	}

	return retval;
}

char* convertBackSlashes(char* src)
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

std::vector<LogString> getFileList(helpers::Pool& p, const File& dir)
{
	apr_dir_t* dir;
	apr_finfo_t entry;
	std::vector<LogString> filenames;

	apr_status_t stat = apr_dir_open(&dir,
			convertBackSlashes(getPath(p, dir)),
			p.getAPRPool());

	if (stat == APR_SUCCESS)
	{
		int style = APR_FILEPATH_ENCODING_UNKNOWN;
		apr_filepath_encoding(&style, p.getAPRPool());
		stat = apr_dir_read(&entry, APR_FINFO_DIRENT, dir);

		while (stat == APR_SUCCESS)
		{
			if (entry.name != NULL)
			{
				LogString filename;

				if (style == APR_FILEPATH_ENCODING_UTF8)
				{
					helpers::Transcoder::decodeUTF8(entry.name, filename);
				}
				else
				{
					helpers::Transcoder::decode(entry.name, filename);
				}

				filenames.push_back(filename);
			}

			stat = apr_dir_read(&entry, APR_FINFO_DIRENT, dir);
		}

		stat = apr_dir_close(dir);
	}

	return filenames;
}

} // namespace LOG4CXX_NS

#if LOG4CXX_FILE_IS_FILESYSTEM_PATH

namespace LOG4CXX_NS
{

bool deleteFile(helpers::Pool&, const File& f)
{
	FileErrorCode ec;
	return remove(f, ec);
}

LogString getPath(const File& f)
{
#if LOG4CXX_LOGCHAR_IS_UTF8
	return f.string();
#elif LOG4CXX_LOGCHAR_IS_WCHAR_T
	return f.wstring();
#else
	return decodeLS(f.wstring());
#endif
}

LogString getParent(helpers::Pool&, const File& f)
{
	LogString result;
	if (f.has_parent_path())
		result = getPath(f.parent_path());
	return result;
}

log4cxx_time_t lastModified(helpers::Pool&, const File& f)
{
	log4cxx_time_t result = 0;
	FileErrorCode ec;
	auto ftime = last_write_time(f, ec);
	if (!ec)
	{
		result = std::chrono::system_clock::to_time_t(clock_cast<std::chrono::system_clock>(ftime));
	}
	return result;
}

size_t length(helpers::Pool&, const File& f)
{
	size_t result = 0;
	FileErrorCode ec;
	auto fsize = file_size(f, ec);
	if (!ec)
	{
		result = static_cast<size_t>(fsize);
	}
	return result;
}

bool mkdirs(helpers::Pool&, const File& f)
{
	FileErrorCode ec;
	return create_directories(f, ec);
}

log4cxx_status_t openFile(const File& f, apr_file_t** file, int flags, int perm, helpers::Pool& p)
{
	return apr_file_open(file, getPath(p, f), flags, perm, p.getAPRPool());
}

} // namespace LOG4CXX_NS

#else // !LOG4CXX_FILE_IS_FILESYSTEM_PATH
#include <assert.h>
#include <log4cxx/helpers/exception.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct File::FilePrivate{
	FilePrivate() :
		autoDelete(false)
	{}

	FilePrivate(LogString path) :
		path(path),
		autoDelete(false)
	{}

	FilePrivate(LogString path, bool autoDelete) :
		path(path),
		autoDelete(autoDelete)
	{}

	LogString path;
	bool autoDelete;
};

File::File() :
	m_priv(std::make_unique<FilePrivate>())
{
}

File::File(const std::string& name)
#if LOG4CXX_LOGCHAR_IS_UTF8
	: m_priv(std::make_unique<FilePrivate>(name))
#else
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name)))
#endif
{
}

File::File(const char* name)
#if LOG4CXX_LOGCHAR_IS_UTF8
	: m_priv(std::make_unique<FilePrivate>(name))
#else
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name)))
#endif
{
}

#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR_T
File::File(const std::wstring& name)
#if LOG4CXX_LOGCHAR_IS_WCHAR_T
	: m_priv(std::make_unique<FilePrivate>(name))
#else
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name)))
#endif
{
}

File::File(const wchar_t* name1)
#if LOG4CXX_LOGCHAR_IS_WCHAR_T
	: m_priv(std::make_unique<FilePrivate>(name))
#else
	: m_priv(std::make_unique<FilePrivate>(decodeLS(name1)))
#endif
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

File& File::operator=(const LogString& newName)
{
	m_priv->path.assign(newName);
	return *this;
}


File::~File()
{
	if(m_priv->autoDelete){
		Pool p;
		deleteFile(p);
	}
}


LogString File::getPath() const
{
	return m_priv->path;
}

File& File::setPath(const LogString& newName)
{
	m_priv->path.assign(newName);
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

char* File::getPath(Pool& p) const
{
	return ::getPath(p, *this);
}

log4cxx_status_t File::open(apr_file_t** file, int flags,
	int perm, Pool& p) const
{
	return apr_file_open(file, getPath(p), flags, perm, p.getAPRPool());
}



bool File::exists(Pool& p) const
{
	apr_finfo_t finfo;
	apr_status_t rv = apr_stat(&finfo, getPath(p),
			0, p.getAPRPool());
	return rv == APR_SUCCESS;
}

char* File::convertBackSlashes(char* src)
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

bool File::deleteFile(Pool& p) const
{
	apr_status_t rv = apr_file_remove(convertBackSlashes(getPath(p)),
			p.getAPRPool());
	return rv == APR_SUCCESS;
}

bool File::renameTo(const File& dest, Pool& p) const
{
	apr_status_t rv = apr_file_rename(convertBackSlashes(getPath(p)),
			convertBackSlashes(dest.getPath(p)),
			p.getAPRPool());
	return rv == APR_SUCCESS;
}


size_t File::length(Pool& pool) const
{
	apr_finfo_t finfo;
	apr_status_t rv = apr_stat(&finfo, getPath(pool),
			APR_FINFO_SIZE, pool.getAPRPool());

	if (rv == APR_SUCCESS)
	{
		return (size_t) finfo.size;
	}

	return 0;
}


log4cxx_time_t File::lastModified(Pool& pool) const
{
	apr_finfo_t finfo;
	apr_status_t rv = apr_stat(&finfo, getPath(pool),
			APR_FINFO_MTIME, pool.getAPRPool());

	if (rv == APR_SUCCESS)
	{
		return finfo.mtime;
	}

	return 0;
}


std::vector<LogString> File::list(Pool& p) const
{
	return getFileList(p, *this);
}
LogString File::getParent(Pool&) const
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

bool File::mkdirs(Pool& p) const
{
	apr_status_t stat = apr_dir_make_recursive(convertBackSlashes(getPath(p)),
			APR_OS_DEFAULT, p.getAPRPool());
	return stat == APR_SUCCESS;
}

void File::setAutoDelete(bool autoDelete){
	m_priv->autoDelete = autoDelete;
}

bool File::getAutoDelete() const{
	return m_priv->autoDelete;
}

#endif // !LOG4CXX_FILE_IS_FILESYSTEM_PATH
