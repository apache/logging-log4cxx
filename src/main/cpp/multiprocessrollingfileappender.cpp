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

#ifdef WIN32 // apr_stat is slow on Windows
#define USING_ROLLOVER_REQUIRED_CHECK_IS_FASTER 1
#else
#define USING_ROLLOVER_REQUIRED_CHECK_IS_FASTER 0
#endif

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::rolling;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;

struct MultiprocessRollingFileAppender::MultiprocessRollingFileAppenderPriv
	: public RollingFileAppenderPriv
{
	FileOutputStreamPtr fileOutputStream;
	apr_file_t* lock_file = NULL;

	~MultiprocessRollingFileAppenderPriv()
	{
		if (lock_file)
			apr_file_close(lock_file);
	}
	/**
	 * Coordinate a rollover with other processes

	 * @return true if this process perfomed the rollover.
	 */
	bool synchronizedRollover
		( Appender*                   appender
		, const spi::LoggingEventPtr& event
		, const LogString&            fileName
		, bool                        append
		, const TriggeringPolicyPtr&  trigger
		);

	/**
	 * Is it possible the current log file was renamed?
	 */
	bool isRolloverCheckNeeded();

	/**
	 *  Was \c fileName renamed?
	 *  @param pSize if not NULL, receives the log file size
	 * @return true if the log file must be reopened
	 */
	bool isAlreadyRolled(const LogString& fileName, size_t* pSize = 0);

	/**
	 * Put the current size of the log file into \c pSize.
	 * @return true if the log file size was put into \c pSize
	 */
	bool getCurrentFileSize(size_t* pSize);

	/**
	 * re-open \c fileName (used after it has been renamed)
	 */
	void reopenFile(const LogString& fileName);

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
						ObjectPtr obj = std::make_shared<Date>(apr_time_now());
						LogString fileNamePattern;
						(*(basePolicy->getPatternConverterList().begin()))->format(obj, fileNamePattern);
						filePrefix.clear();
						Transcoder::encode(fileNamePattern, filePrefix);
					}
				}
				std::string lockFileName = filePrefix + ".lock";
				// Create the lock file with owner-only permissions: the cooperating
				// processes run under the same uid, and any other local user able to
				// take a shared fcntl lock on a world-readable lock file could block
				// rollover (and with it every logging thread) indefinitely.
				auto stat = apr_file_open(&m_parent->lock_file, lockFileName.c_str(), APR_CREATE | APR_READ | APR_WRITE, APR_FPROT_UREAD | APR_FPROT_UWRITE, m_parent->pool.getAPRPool());
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

	helpers::WriterPtr createWriter(const helpers::OutputStreamPtr& os) override;
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
void MultiprocessRollingFileAppender::activateOptions(  )
{
	if (_priv->activateOptions())
	{
		_priv->activate();
	}

	if (auto pTimeBased = LOG4CXX_NS::cast<TimeBasedRollingPolicy>(_priv->rollingPolicy))
		pTimeBased->setMultiprocess(true);
}

/**
 * Is it possible the current log file was renamed?
 */
bool MultiprocessRollingFileAppender::MultiprocessRollingFileAppenderPriv::isRolloverCheckNeeded()
{
	bool result = true;
#if USING_ROLLOVER_REQUIRED_CHECK_IS_FASTER
	if (auto pTimeBased = LOG4CXX_NS::cast<TimeBasedRollingPolicy>(this->rollingPolicy))
		result = !pTimeBased->isLastFileNameUnchanged();
#endif
	return result;
}

/**
 * Was \c fileName renamed?
 */
bool MultiprocessRollingFileAppender::MultiprocessRollingFileAppenderPriv::isAlreadyRolled(const LogString& fileName, size_t* pSize)
{
	if( !this->fileOutputStream || !this->fileOutputStream->getFilePtr() )
		return false;
	apr_int32_t wantedInfo = APR_FINFO_IDENT;
	if (pSize)
		wantedInfo |= APR_FINFO_SIZE;
	apr_finfo_t finfo1;
	apr_status_t st1 = apr_file_info_get(&finfo1, wantedInfo, this->fileOutputStream->getFilePtr());

	if (st1 != APR_SUCCESS)
		LogLog::warn(LOG4CXX_STR("apr_file_info_get failed"));
	else if (pSize)
		*pSize = finfo1.size;

	LOG4CXX_ENCODE_CHAR(fname, fileName);
	apr_status_t st2;
	apr_finfo_t finfo2;
	int retryCount = 0;
	while (APR_SUCCESS != (st2 = apr_stat(&finfo2, fname.c_str(), wantedInfo, this->pool.getAPRPool())))
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
bool MultiprocessRollingFileAppender::MultiprocessRollingFileAppenderPriv::getCurrentFileSize(size_t* pSize)
{
	if( !this->fileOutputStream || !this->fileOutputStream->getFilePtr() )
		return false;
	apr_int32_t wantedInfo = APR_FINFO_SIZE;
	apr_finfo_t finfo;
	if (apr_file_info_get(&finfo, wantedInfo, this->fileOutputStream->getFilePtr()) != APR_SUCCESS)
	{
		LogLog::warn(LOG4CXX_STR("apr_file_info_get failed"));
		return false;
	}
	*pSize = finfo.size;
	return true;
}

/**
 * Coordinate a rollover with other processes

 * @return true if this process perfomed the rollover.
 */
bool MultiprocessRollingFileAppender::MultiprocessRollingFileAppenderPriv::synchronizedRollover
	( Appender*                   appender
	, const spi::LoggingEventPtr& event
	, const LogString&            fileName
	, bool                        append
	, const TriggeringPolicyPtr&  trigger
	)
{
	bool result = false;
	if (!this->rollingPolicy)
		; // can't roll without a policy
	else if (this->isAlreadyRolled(fileName, &this->fileLength))
		this->reopenFile(fileName);
	else
	{
		MultiprocessRollingFileAppenderPriv::Lock lk(this, fileName);
		if (!lk.hasLock())
			LogLog::warn(LOG4CXX_STR("Failed to lock ") + fileName);
		else if (this->isAlreadyRolled(fileName, &this->fileLength))
			this->reopenFile(fileName);
		else if (!trigger || trigger->isTriggeringEvent(appender, event, fileName, this->fileLength))
			result = this->rollover(fileName, append);
	}

	return result;
}

/**
 * re-open \c fileName (used after it has been renamed)
 */
void MultiprocessRollingFileAppender::MultiprocessRollingFileAppenderPriv::reopenFile(const LogString& fileName)
{
	this->close();
#if USING_ROLLOVER_REQUIRED_CHECK_IS_FASTER
	if (auto pTimeBased = LOG4CXX_NS::cast<TimeBasedRollingPolicy>(this->rollingPolicy))
		pTimeBased->loadLastFileName();
#endif
	this->targetFile.setPath(fileName);
	auto os = std::make_shared<FileOutputStream>(fileName, true, this->lazyFileCreation);
	this->setWriter(this->createWriter(os));
}

void MultiprocessRollingFileAppender::subAppend( const spi::LoggingEventPtr& event )
{
	// The rollover check must precede actual writing. This is the
	// only correct behavior for time driven triggers.
	auto fileName = getFile();
	if (_priv->triggeringPolicy->isTriggeringEvent(this, event, fileName, _priv->fileLength))
	{
		//
		//   wrap rollover request in try block since
		//    rollover may fail in case read access to directory
		//    is not provided.  However appender should still be in good
		//     condition and the append should still happen.
		try
		{
			_priv->synchronizedRollover(this, event, fileName, getAppend(), _priv->triggeringPolicy);
		}
		catch (std::exception& ex)
		{
			LogString msg(LOG4CXX_STR("Rollover of ["));
			msg.append(fileName);
			msg.append(LOG4CXX_STR("] failed"));
			_priv->errorHandler->error(msg, ex, 0);
		}
	}
	else if (!_priv->isRolloverCheckNeeded())
		_priv->getCurrentFileSize(&_priv->fileLength);
	else if (_priv->isAlreadyRolled(fileName, &_priv->fileLength))
		_priv->reopenFile(fileName);

	FileAppender::subAppend( event );
}

WriterPtr MultiprocessRollingFileAppender::MultiprocessRollingFileAppenderPriv::createWriter(const OutputStreamPtr& os)
{
	auto fos = LOG4CXX_NS::cast<FileOutputStream>(os);
	if( fos )
		this->fileOutputStream = fos;
	else
	{
		LogString msg(LOG4CXX_STR("Can't cast stream to FileOutputStream"));
		msg += LOG4CXX_STR(" - Rollover synchronization will be degraded.");
		this->errorHandler->error(msg);
	}
	return RollingFileAppenderPriv::createWriter(os);
}

