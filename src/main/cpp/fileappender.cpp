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
#include <log4cxx/fileappender.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/helpers/outputstreamwriter.h>
#include <log4cxx/helpers/bufferedwriter.h>
#include <log4cxx/helpers/bytebuffer.h>
#include "log4cxx/helpers/threadutility.h"
#include <log4cxx/private/writerappender_priv.h>
#include <log4cxx/private/fileappender_priv.h>
#include <limits>
#include <mutex>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;

IMPLEMENT_LOG4CXX_OBJECT(FileAppender)

#define _priv static_cast<FileAppenderPriv*>(m_priv.get())

FileAppender::FileAppender() :
	WriterAppender (std::make_unique<FileAppenderPriv>())
{
}

FileAppender::FileAppender
	( const LayoutPtr& layout
	, const LogString& fileName
	, bool             appendToFile
	, bool             useBufferedOutput
	, int              bufferByteCount
	)
	: WriterAppender(std::make_unique<FileAppenderPriv>(layout, fileName, appendToFile, useBufferedOutput, bufferByteCount))
{
	_priv->activate();
}

FileAppender::FileAppender(std::unique_ptr<FileAppenderPriv> priv)
	: WriterAppender (std::move(priv))
{
}

FileAppender::~FileAppender()
{
	if (auto p = _priv->taskManager.lock())
		p->value().removePeriodicTask(_priv->flushTaskName);
	if (_priv->flushTask)
		_priv->flushTask->detach(); // Blocks until any in-flight flush completes
}

void FileAppender::setAppend(bool fileAppend1)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	_priv->fileAppend = fileAppend1;
}

void FileAppender::setFile(const LogString& file)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	_priv->targetFile.setPath(file);
}

void FileAppender::setBufferedIO(bool bufferedIO1)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	_priv->bufferedIO = bufferedIO1;
}

void FileAppender::setOption(const LogString& option,
	const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("FILE"), LOG4CXX_STR("file"))
		|| StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("FILENAME"), LOG4CXX_STR("filename")))
	{
		std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
		_priv->targetFile.setPath(stripDuplicateBackslashes(value));
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("APPEND"), LOG4CXX_STR("append")))
	{
		std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
		_priv->fileAppend = OptionConverter::toBoolean(value, true);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("BUFFEREDIO"), LOG4CXX_STR("bufferedio")))
	{
		std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
		_priv->bufferedIO = OptionConverter::toBoolean(value, false);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("IMMEDIATEFLUSH"), LOG4CXX_STR("immediateflush")))
	{
		std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
		_priv->bufferedIO = !OptionConverter::toBoolean(value, false);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("BUFFERSIZE"), LOG4CXX_STR("buffersize")))
	{
		std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
		long parsed = OptionConverter::toFileSize(value, 8 * 1024);
		if (parsed < 0 || parsed > static_cast<long>((std::numeric_limits<int>::max)()))
		{
			LogLog::warn(LOG4CXX_STR("FileAppender BufferSize is out of range. Using the default value."));
			parsed = 8 * 1024;
		}
		_priv->bufferSize = static_cast<int>(parsed);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("BUFFEREDSECONDS"), LOG4CXX_STR("bufferedseconds")))
	{
		std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
		_priv->bufferedSeconds = OptionConverter::toInt(value, 0);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("LAZYFILECREATION"), LOG4CXX_STR("lazyfilecreation")))
	{
		std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
		_priv->lazyFileCreation = OptionConverter::toBoolean(value, false);
	}
	else
	{
		WriterAppender::setOption(option, value);
	}
}

void FileAppender::activateOptions(  )
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	// It does not make sense to have immediate flush and bufferedIO.
	if (_priv->bufferedIO)
	   setImmediateFlush(false);
	_priv->activate();
}

void FileAppender::FileAppenderPriv::activate()
{
	int errors = 0;

	if (this->targetFile.hasPath())
	{
		try
		{
			this->open();
		}
		catch (const IOException& e)
		{
			errors++;
			LogString msg(LOG4CXX_STR("setFile("));
			msg.append(this->targetFile.getPath());
			msg.append(1, (logchar) 0x2C /* ',' */);
			StringHelper::toString(this->fileAppend, msg);
			msg.append(LOG4CXX_STR(") call failed."));
			this->errorHandler->error(msg, e, ErrorCode::FILE_OPEN_FAILURE);
		}
	}
	else
	{
		errors++;
		LogLog::error(LogString(LOG4CXX_STR("File option not set for appender ["))
			+  this->name + LOG4CXX_STR("]."));
		LogLog::warn(LOG4CXX_STR("Are you using FileAppender instead of ConsoleAppender?"));
	}

	if (errors == 0)
	{
		this->checkConfiguration();
		if (auto p = this->taskManager.lock())
			p->value().removePeriodicTask(this->flushTaskName);

		if (!this->bufferedIO)
			;
		else if (0 < this->bufferedSeconds)
		{
			auto taskManager = ThreadUtility::instancePtr();
			if (!this->flushTask)
			{
				this->flushTask = std::make_shared<FileAppenderPriv::FlushTask>();
				this->flushTask->priv = this;
			}
			// Key the task by a unique name
			this->flushTaskName = this->targetFile.getName();
			this->flushTaskName.append(1, (logchar) 0x23 /* '#' */);
			StringHelper::toString(reinterpret_cast<size_t>(this), this->flushTaskName);
			auto flushTask = this->flushTask;
			taskManager->value().addPeriodicTask(this->flushTaskName
				, [flushTask]() { flushTask->run(); }
				, std::chrono::seconds(this->bufferedSeconds)
				);
			this->taskManager = taskManager;
		}
	}
}


/**
 * Replaces double backslashes (except the leading doubles of UNC's)
 * with single backslashes for compatibility with existing path
 * specifications that were working around use of
 * OptionConverter::convertSpecialChars in XML configuration files.
 *
 * @param src source string
 * @return modified string
 *
 *
 */
LogString FileAppender::stripDuplicateBackslashes(const LogString& src)
{
	logchar backslash = 0x5C; // '\\'
	LogString::size_type i = src.find_last_of(backslash);

	if (i != LogString::npos)
	{
		LogString tmp(src);

		for (;
			i != LogString::npos && i > 0;
			i = tmp.find_last_of(backslash, i - 1))
		{
			//
			//   if the preceding character is a slash then
			//      remove the preceding character
			//      and continue processing
			if (tmp[i - 1] == backslash)
			{
				tmp.erase(i, 1);
				i--;

				if (i == 0)
				{
					break;
				}
			}
			else
			{
				//
				//  if there an odd number of slashes
				//     the string wasn't trying to work around
				//     OptionConverter::convertSpecialChars
				return src;
			}
		}

		return tmp;
	}

	return src;
}

void FileAppender::FileAppenderPriv::open()
{
	this->close();

	bool writeBOM = false;

	if (StringHelper::equalsIgnoreCase(this->encoding,
			LOG4CXX_STR("utf-16"), LOG4CXX_STR("UTF-16")))
	{
		//
		//    don't want to write a byte order mark if the file exists
		//
		if (this->fileAppend)
		{
			writeBOM = !this->targetFile.exists();
		}
		else
		{
			writeBOM = true;
		}
	}

	OutputStreamPtr outStream;

	if (this->lazyFileCreation)
	{
		LogString parentName = this->targetFile.getParent();

		if (!parentName.empty())
		{
			File parentDir(parentName);

			if (!parentDir.exists())
			{
				LogLog::debug(LOG4CXX_STR("Creating dirs ") + parentDir.getPath());
				// The file is not opened here, so a failure must be reported now.
				if (!parentDir.mkdirs() && !parentDir.exists())
				{
					throw IOException(LOG4CXX_STR("Unable to create directory ") + parentDir.getPath());
				}
			}
		}

		outStream = std::make_shared<FileOutputStream>(this->targetFile.getPath(), this->fileAppend, true);
	}
	else
	{
		try
		{
			outStream = std::make_shared<FileOutputStream>(this->targetFile.getPath(), this->fileAppend);
		}
		catch (const IOException&)
		{
			LogString parentName = this->targetFile.getParent();

			if (!parentName.empty())
			{
				File parentDir(parentName);

				if (!parentDir.exists() && parentDir.mkdirs())
				{
					outStream = std::make_shared<FileOutputStream>(this->targetFile.getPath(), this->fileAppend);
				}
				else
				{
					throw;
				}
			}
			else
			{
				throw;
			}
		}
	}


	//
	//   if a new file and UTF-16, then write a BOM
	//
	if (writeBOM)
	{
		Pool p;
		char bom[] = { (char) 0xFE, (char) 0xFF };
		ByteBuffer buf(bom, 2);
		outStream->write(buf);
	}

	WriterPtr newWriter(this->createWriter(outStream));

	if (this->bufferedIO)
	{
		newWriter = std::make_shared<BufferedWriter>(newWriter, this->bufferSize);
	}

	this->setWriter(newWriter);

	this->writeHeader();

}

LogString FileAppender::getFile() const
{
	return _priv->targetFile.getPath();
}

bool FileAppender::getBufferedIO() const
{
	return _priv->bufferedIO;
}

int FileAppender::getBufferSize() const
{
	return _priv->bufferSize;
}

int FileAppender::getBufferedSeconds() const
{
	return _priv->bufferedSeconds;
}

void FileAppender::setBufferSize(int newValue)
{
	if (newValue < 0)
	{
		LogLog::warn(LOG4CXX_STR("FileAppender BufferSize must be non-negative. Using zero."));
		newValue = 0;
	}
	_priv->bufferSize = newValue;
}

void FileAppender::setBufferedSeconds(int newValue)
{
	_priv->bufferedSeconds = newValue;
}

bool FileAppender::getAppend() const
{
	return _priv->fileAppend;
}

void FileAppender::setLazyFileCreation(bool newValue)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	_priv->lazyFileCreation = newValue;
}

bool FileAppender::getLazyFileCreation() const
{
	return _priv->lazyFileCreation;
}

