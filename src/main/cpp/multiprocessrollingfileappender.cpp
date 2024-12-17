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

#include <apr_portable.h>
#include <apr_file_io.h>
#include <apr_mmap.h>
#ifndef MAX_FILE_LEN
	#define MAX_FILE_LEN 2048
#endif
#include <log4cxx/pattern/filedatepatternconverter.h>
#include <log4cxx/helpers/date.h>

#include <log4cxx/rolling/multiprocessrollingfileappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/rolling/rolloverdescription.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/bufferedwriter.h>
#include <log4cxx/rolling/manualtriggeringpolicy.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/private/rollingfileappender_priv.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>
#include <mutex>
#include <thread>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::rolling;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;

struct MultiprocessRollingFileAppender::MultiprocessRollingFileAppenderPriv
	: public RollingFileAppenderPriv
{
	~MultiprocessRollingFileAppenderPriv()
	{
		if (lock_file)
			apr_file_close(lock_file);
	}

	apr_file_t* log_file = NULL;
	apr_file_t* lock_file = NULL;

public: // Support classes
	class Lock
	{
		MultiprocessRollingFileAppenderPriv* m_parent;
		LogString m_lockFileName;
		bool m_ok;
	public: // ...structors
		/**
		 *  Get an exclusive file lock
		 */
		Lock(MultiprocessRollingFileAppenderPriv* parent, const LogString& fileName)
			: m_parent(parent)
			, m_ok(false)
		{
			if (!m_parent->lock_file)
			{
				std::string filePrefix;
				Transcoder::encode(fileName, filePrefix);
				if (auto basePolicy = LOG4CXX_NS::cast<RollingPolicyBase>(m_parent->rollingPolicy))
				{
					if (basePolicy->getPatternConverterList().size())
					{
						Pool p;
						ObjectPtr obj = std::make_shared<Date>(apr_time_now());
						LogString fileNamePattern;
						(*(basePolicy->getPatternConverterList().begin()))->format(obj, fileNamePattern, p);
						filePrefix.clear();
						Transcoder::encode(fileNamePattern, filePrefix);
					}
				}
				std::string lockFileName = filePrefix + ".lock";
				auto stat = apr_file_open(&m_parent->lock_file, lockFileName.c_str(), APR_CREATE | APR_READ | APR_WRITE, APR_OS_DEFAULT, m_parent->pool.getAPRPool());
				if (stat != APR_SUCCESS)
				{
					LogString err;
					Transcoder::decode(lockFileName, err);
					err += LOG4CXX_STR(": apr_file_open: ");
					Transcoder::decode(strerror(errno), err);
					LogLog::warn(err);
					m_parent->lock_file = NULL;
				}
			}
			if (m_parent->lock_file)
			{
				if (apr_file_lock(m_parent->lock_file, APR_FLOCK_EXCLUSIVE) != APR_SUCCESS)
				{
					LogString err;
					Transcoder::decode(fileName, err);
					err += LOG4CXX_STR(": apr_file_lock: ");
					Transcoder::decode(strerror(errno), err);
					LogLog::warn(err);
				}
				else
					m_ok = true;
			}
		}

		/**
		 *  Release the file lock
		 */
		~Lock()
		{
			if (m_parent->lock_file)
			{
				if (apr_file_unlock(m_parent->lock_file) != APR_SUCCESS)
				{
					LogLog::warn(LOG4CXX_STR("apr_file_unlock failed"));
				}
			}
		}
	public: // Accessors
		bool hasLock() const { return m_ok; }
	};
};

#define _priv static_cast<MultiprocessRollingFileAppenderPriv*>(m_priv.get())

IMPLEMENT_LOG4CXX_OBJECT(MultiprocessRollingFileAppender)

/**
 * Construct a new instance.
 */
MultiprocessRollingFileAppender::MultiprocessRollingFileAppender()
	: RollingFileAppender(std::make_unique<MultiprocessRollingFileAppenderPriv>())
{
}

/**
 * Prepare instance of use.
 */
void MultiprocessRollingFileAppender::activateOptions(Pool& p)
{
	RollingFileAppender::activateOptions(p);

	if (auto pTimeBased = LOG4CXX_NS::cast<TimeBasedRollingPolicy>(_priv->rollingPolicy))
		pTimeBased->setMultiprocess(true);
}

/**
 * Is it possible the current log file was renamed?
 */
bool MultiprocessRollingFileAppender::isRolloverCheckNeeded()
{
	bool result = true;
#ifdef WIN32 // apr_stat is slow on Windows
	if (auto pTimeBased = LOG4CXX_NS::cast<TimeBasedRollingPolicy>(_priv->rollingPolicy))
		result = !pTimeBased->isLastFileNameUnchanged();
#endif
	return result;
}

/**
 * Was \c fileName renamed?
 */
bool MultiprocessRollingFileAppender::isAlreadyRolled(const LogString& fileName, size_t* pSize)
{
	if( !_priv->log_file )
		return false;
	apr_int32_t wantedInfo = APR_FINFO_IDENT;
	if (pSize)
		wantedInfo |= APR_FINFO_SIZE;
	apr_finfo_t finfo1;
	apr_status_t st1 = apr_file_info_get(&finfo1, wantedInfo, _priv->log_file);

	if (st1 != APR_SUCCESS)
		LogLog::warn(LOG4CXX_STR("apr_file_info_get failed"));
	else if (pSize)
		*pSize = finfo1.size;

	LOG4CXX_ENCODE_CHAR(fname, fileName);
	apr_status_t st2;
	apr_finfo_t finfo2;
	int retryCount = 0;
	while (APR_SUCCESS != (st2 = apr_stat(&finfo2, fname.c_str(), wantedInfo, _priv->pool.getAPRPool())))
	{
		if (5 == ++retryCount)
			break;
		using namespace std::chrono_literals;
		std::this_thread::sleep_for(30ms);
	}
	if (st2 != APR_SUCCESS)
		LogLog::warn(fileName + LOG4CXX_STR(": apr_stat failed."));
	else if (pSize)
		*pSize = finfo2.size;

	return st2 != APR_SUCCESS ||
		((st1 == APR_SUCCESS) && (st2 == APR_SUCCESS) &&
		((finfo1.device != finfo2.device) || (finfo1.inode != finfo2.inode)));
}

/**
 * Put the current size of the log file into \c pSize.
 */
bool MultiprocessRollingFileAppender::getCurrentFileSize(size_t* pSize)
{
	if( !_priv->log_file )
		return false;
	apr_int32_t wantedInfo = APR_FINFO_SIZE;
	apr_finfo_t finfo;
	if (apr_file_info_get(&finfo, wantedInfo, _priv->log_file) != APR_SUCCESS)
	{
		LogLog::warn(LOG4CXX_STR("apr_file_info_get failed"));
		return false;
	}
	*pSize = finfo.size;
	return true;
}

/**
   Implements the usual roll over behaviour.

   <p>If <code>MaxBackupIndex</code> is positive, then files
   {<code>File.1</code>, ..., <code>File.MaxBackupIndex -1</code>}
   are renamed to {<code>File.2</code>, ...,
   <code>File.MaxBackupIndex</code>}. Moreover, <code>File</code> is
   renamed <code>File.1</code> and closed. A new <code>File</code> is
   created to receive further log output.

   <p>If <code>MaxBackupIndex</code> is equal to zero, then the
   <code>File</code> is truncated with no backup files created.

 * @return true if rollover performed.
 */
bool MultiprocessRollingFileAppender::rollover(Pool& p)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	return synchronizedRollover(p);
}

/**
 * Coordinate a rollover with other processes

 * @return true if this process perfomed the rollover.
 */
bool MultiprocessRollingFileAppender::synchronizedRollover(Pool& p, const TriggeringPolicyPtr& trigger)
{
	bool result = false;
	LogString fileName = getFile();
	if (!_priv->rollingPolicy)
		; // can't roll without a policy
	else if (isAlreadyRolled(fileName, &_priv->fileLength))
		reopenFile(fileName);
	else
	{
		MultiprocessRollingFileAppenderPriv::Lock lk(_priv, fileName);
		if (!lk.hasLock())
			LogLog::warn(LOG4CXX_STR("Failed to lock ") + fileName);
		else if (isAlreadyRolled(fileName, &_priv->fileLength))
			reopenFile(fileName);
		else if (trigger && !trigger->isTriggeringEvent(this, _priv->_event, fileName, _priv->fileLength))
			;
		else if (auto rollover1 = _priv->rollingPolicy->rollover(fileName, getAppend(), p))
		{
			closeWriter();
			if (rollover1->getActiveFileName() == fileName)
			{
				bool success = true; // A synchronous action is not required
				if (auto pAction = rollover1->getSynchronous())
					success = pAction->execute(p);

				bool appendToExisting = true;
				if (success)
				{
					appendToExisting = rollover1->getAppend();
					if (appendToExisting)
					{
						_priv->fileLength = File().setPath(rollover1->getActiveFileName()).length(p);
					}
					else
					{
						_priv->fileLength = 0;
					}

					if (auto asyncAction = rollover1->getAsynchronous())
					{
						try
						{
							asyncAction->execute(p);
						}
						catch (std::exception& ex)
						{
							LogString msg(LOG4CXX_STR("Async action in rollover ["));
							msg.append(fileName);
							msg.append(LOG4CXX_STR("] failed"));
							_priv->errorHandler->error(msg, ex, 0);
						}
					}
				}
				else
				{
					LogString msg(LOG4CXX_STR("Rollover of ["));
					msg.append(fileName);
					msg.append(LOG4CXX_STR("] failed"));
					_priv->errorHandler->error(msg);
				}
				setFileInternal(rollover1->getActiveFileName(), appendToExisting, _priv->bufferedIO, _priv->bufferSize, p);
			}
			else
			{
				setFileInternal(rollover1->getActiveFileName());
				// Call activateOptions to create any intermediate directories(if required)
				FileAppender::activateOptionsInternal(p);
				OutputStreamPtr os = std::make_shared<FileOutputStream>
					( rollover1->getActiveFileName()
					, rollover1->getAppend()
					);
				setWriterInternal(createWriter(os));

				bool success = true; // A synchronous action is not required
				if (auto pAction = rollover1->getSynchronous())
					success = pAction->execute(p);

				if (success)
				{
					if (rollover1->getAppend())
					{
						_priv->fileLength = File().setPath(rollover1->getActiveFileName()).length(p);
					}
					else
					{
						_priv->fileLength = 0;
					}

					if (auto asyncAction = rollover1->getAsynchronous())
					{
						try
						{
							asyncAction->execute(p);
						}
						catch (std::exception& ex)
						{
							LogString msg(LOG4CXX_STR("Async action in rollover ["));
							msg.append(fileName);
							msg.append(LOG4CXX_STR("] failed"));
							_priv->errorHandler->error(msg, ex, 0);
						}
					}
				}
			}

			result = true;
		}
	}

	return result;
}

/**
 * re-open \c fileName (used after it has been renamed)
 */
void MultiprocessRollingFileAppender::reopenFile(const LogString& fileName)
{
	closeWriter();
	OutputStreamPtr os = std::make_shared<FileOutputStream>(fileName, true);
	WriterPtr newWriter(createWriter(os));
	setFile(fileName);
	setWriter(newWriter);
}

/**
 * {@inheritDoc}
*/
void MultiprocessRollingFileAppender::subAppend(const LoggingEventPtr& event, Pool& p)
{
	// The rollover check must precede actual writing. This is the
	// only correct behavior for time driven triggers.
	LogString fileName = getFile();
	if (_priv->triggeringPolicy->isTriggeringEvent(this, event, fileName, _priv->fileLength))
	{
		//
		//   wrap rollover request in try block since
		//    rollover may fail in case read access to directory
		//    is not provided.  However appender should still be in good
		//     condition and the append should still happen.
		try
		{
			_priv->_event = event;
			synchronizedRollover(p, _priv->triggeringPolicy);
		}
		catch (std::exception& ex)
		{
			LogString msg(LOG4CXX_STR("Rollover of ["));
			msg.append(fileName);
			msg.append(LOG4CXX_STR("] failed"));
			_priv->errorHandler->error(msg, ex, 0);
		}
	}
	else if (!isRolloverCheckNeeded())
		getCurrentFileSize(&_priv->fileLength);
	else if (isAlreadyRolled(fileName, &_priv->fileLength))
		reopenFile(fileName);

	FileAppender::subAppend(event, p);
}

/**
   Returns an OutputStreamWriter when passed an OutputStream.  The
   encoding used will depend on the value of the
   <code>encoding</code> property.  If the encoding value is
   specified incorrectly the writer will be opened using the default
   system encoding (an error message will be printed to the loglog.
 @param os output stream, may not be null.
 @return new writer.
 */
WriterPtr MultiprocessRollingFileAppender::createWriter(OutputStreamPtr& os)
{
	auto fos = LOG4CXX_NS::cast<FileOutputStream>(os);
	if( fos )
		_priv->log_file = fos->getFilePtr();
	else
	{
		LogString msg(LOG4CXX_STR("Can't cast stream to FileOutputStream"));
		msg += LOG4CXX_STR(" - Rollover synchronization will be degraded.");
		_priv->errorHandler->error(msg);
	}
	return RollingFileAppender::createWriter(os);
}


void MultiprocessRollingFileAppender::setFileLength(size_t length)
{
	_priv->fileLength = length;
}
