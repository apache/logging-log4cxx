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
#include <log4cxx/helpers/transcoder.h>
#include <assert.h>
#include <log4cxx/helpers/exception.h>
#include <fstream>
#include <filesystem>

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

log4cxx_status_t File::open(std::fstream* file_stream, int flags, int perm) const
{
    file_stream->open(m_priv->path);
    if(file_stream->is_open()){
        return 0;
    }
    return -1;
}

bool File::exists() const
{
    return std::filesystem::exists(m_priv->path);
}

bool File::deleteFile() const
{
    return std::filesystem::remove(m_priv->path);
}

bool File::renameTo(const File& dest) const
{
    std::error_code ec;
    std::filesystem::rename(m_priv->path, dest.getPath(), ec);
    if(ec){
        return false;
    }
    return true;
}


size_t File::length() const
{
    return std::filesystem::file_size(m_priv->path);
}


log4cxx_time_t File::lastModified() const
{
    return std::filesystem::last_write_time(m_priv->path);
}


std::vector<LogString> File::list() const
{
	std::vector<LogString> filenames;

    if(!std::filesystem::is_directory(m_priv->path)){
        return filenames;
    }

    for(auto const& dir_entry : std::filesystem::directory_iterator(m_priv->path)){
        LogString filename;
        const std::filesystem::path file_path = dir_entry.path();

        Transcoder::decode(file_path.filename(), filename);

        filenames.push_back(filename);
    }

	return filenames;
}

LogString File::getParent() const
{
    LogString parent = std::filesystem::path(m_priv->path).parent_path();

	return parent;
}

bool File::mkdirs() const
{
    return std::filesystem::create_directories(m_priv->path);
}

void File::setAutoDelete(bool autoDelete){
	m_priv->autoDelete = autoDelete;
}

bool File::getAutoDelete() const{
	return m_priv->autoDelete;
}
