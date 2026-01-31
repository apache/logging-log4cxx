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
#include <fstream>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct FileOutputStream::FileOutputStreamPrivate
{
    FileOutputStreamPrivate(){}

    std::ofstream file_out;
};

IMPLEMENT_LOG4CXX_OBJECT(FileOutputStream)

FileOutputStream::FileOutputStream(const LogString& filename,
	bool append) : m_priv(std::make_unique<FileOutputStreamPrivate>())
{
    open(m_priv->file_out, filename, append);
}

FileOutputStream::FileOutputStream(const logchar* filename,
	bool append) : m_priv(std::make_unique<FileOutputStreamPrivate>())
{
    open(m_priv->file_out, filename, append);
}

bool FileOutputStream::open(std::ofstream& fout, const LogString& filename,
    bool append)
{
    auto open_mode = std::ios_base::out;
    if(!append){
        open_mode |= std::ios_base::trunc;
    }else{
        open_mode |= std::ios_base::ate;
    }
    fout.open(filename.c_str(), open_mode);
    if(!fout.is_open()){
        throw IOException(filename);
    }

    return true;
}

FileOutputStream::~FileOutputStream()
{
}

void FileOutputStream::close()
{
    if (m_priv->file_out.is_open())
	{
        m_priv->file_out.close();
	}
}

void FileOutputStream::flush()
{
    m_priv->file_out.flush();
}

void FileOutputStream::write(ByteBuffer& buf)
{
    size_t nbytes = buf.remaining();
	const char* data = buf.data();

    m_priv->file_out.write(data, nbytes);
}

std::ofstream* FileOutputStream::getFilePtr() const{
    return &m_priv->file_out;
}

