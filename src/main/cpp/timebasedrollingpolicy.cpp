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
#define NOMINMAX /* tell windows to not define min/max macros */
#include <log4cxx/log4cxx.h>
#include <log4cxx/logstring.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>
#include <log4cxx/pattern/filedatepatternconverter.h>
#include <log4cxx/helpers/date.h>
#include <log4cxx/rolling/filerenameaction.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/rolling/gzcompressaction.h>
#include <log4cxx/rolling/zipcompressaction.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/fileappender.h>
#include <iostream>
#include <apr_mmap.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::rolling;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::pattern;

IMPLEMENT_LOG4CXX_OBJECT(TimeBasedRollingPolicy)

struct TimeBasedRollingPolicy::TimeBasedRollingPolicyPrivate{
#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
	TimeBasedRollingPolicyPrivate() :
		_mmap(nullptr),
		_file_map(nullptr),
		_lock_file(nullptr),
		bAlreadyInitialized(false),
		bRefreshCurFile(false){}
#else
	TimeBasedRollingPolicyPrivate(){}
#endif

		/**
		 * Time for next determination if time for rollover.
		 */
		log4cxx_time_t nextCheck;

		/**
		 * File name at last rollover.
		 */
		LogString lastFileName;

		/**
		 * Length of any file type suffix (.gz, .zip).
		 */
		int suffixLength;

		/**
		 * mmap pointer
		 */
		apr_mmap_t* _mmap;

		/*
		 * pool for mmap handler
		 * */
		LOG4CXX_NS::helpers::Pool _mmapPool;

		/**
		 * mmap file descriptor
		 */
		apr_file_t* _file_map;

		/**
		 * mmap file name
		 */
		std::string _mapFileName;

		/*
		 * lock file handle
		 * */
		apr_file_t* _lock_file;

		/**
		 * Check nextCheck if it has already been set
		 * Timebased rolling policy has an issue when working at low rps.
		 * Under low rps, multiple processes will not be scheduled in time for the second chance(do rolling),
		 * so the rolling mechanism will not be triggered even if the time period is out of date.
		 * This results in log entries will be accumulated for serveral minutes to be rolling.
		 * Adding this flag to provide rolling opportunity for a process even if it is writing the first log entry
		 */
		bool bAlreadyInitialized;

		/*
		 * If the current file name contains date information, retrieve the current writting file from mmap
		 * */
		bool bRefreshCurFile;

		/*
		 * mmap file name
		 * */
		LogString _fileNamePattern;

		bool multiprocess = false;
		bool throwIOExceptionOnForkFailure = true;
};


#define MMAP_FILE_SUFFIX ".map"
#define LOCK_FILE_SUFFIX ".maplck"
#define MAX_FILE_LEN 2048

#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
bool TimeBasedRollingPolicy::isMapFileEmpty(LOG4CXX_NS::helpers::Pool& pool)
{
	apr_finfo_t finfo;
	apr_status_t st = apr_stat(&finfo, m_priv->_mapFileName.c_str(), APR_FINFO_SIZE, pool.getAPRPool());

	if (st != APR_SUCCESS)
	{
		LogLog::warn(helpers::Exception::makeMessage(LOG4CXX_STR("apr_stat"), st));
	}

	if (st == APR_SUCCESS && (0 == finfo.size ||
		(m_priv->_mmap && 0 == *static_cast<logchar*>(m_priv->_mmap->mm))))
	{
		return true;
	}

	return false;
}

void TimeBasedRollingPolicy::initMMapFile(const LogString& lastFileName, LOG4CXX_NS::helpers::Pool& pool)
{
	int iRet = 0;

	if (!m_priv->_mmap)
	{
		LOG4CXX_ENCODE_CHAR(mapFile, m_priv->_fileNamePattern);
		iRet = createMMapFile(mapFile, pool);
	}

	if (!iRet && isMapFileEmpty(pool))
	{
		lockMMapFile(APR_FLOCK_EXCLUSIVE);
		memset(m_priv->_mmap->mm, 0, MAX_FILE_LEN);
		size_t byteCount = sizeof (logchar) * lastFileName.size();
		if (byteCount <= MAX_FILE_LEN - sizeof (logchar))
			memcpy(m_priv->_mmap->mm, lastFileName.c_str(), byteCount);
		unLockMMapFile();
	}
}

const std::string TimeBasedRollingPolicy::createFile(const std::string& fileName, const std::string& suffix, LOG4CXX_NS::helpers::Pool& pool)
{
	char szUid[MAX_FILE_LEN] = "0000";
#ifndef _WIN32 // The uid provided by the Windows version of apr_uid_current is not a constant value
	apr_uid_t uid;
	apr_gid_t groupid;
	if (APR_SUCCESS == apr_uid_current(&uid, &groupid, pool.getAPRPool()))
		snprintf(szUid, MAX_FILE_LEN, "%u", uid);
#endif
	return fileName + szUid + suffix;
}

int TimeBasedRollingPolicy::createMMapFile(const std::string& fileName, LOG4CXX_NS::helpers::Pool& pool)
{
	m_priv->_mapFileName = createFile(fileName, MMAP_FILE_SUFFIX, pool);

	apr_status_t stat = apr_file_open(&m_priv->_file_map, m_priv->_mapFileName.c_str(), APR_CREATE | APR_READ | APR_WRITE, APR_OS_DEFAULT, m_priv->_mmapPool.getAPRPool());

	if (stat != APR_SUCCESS)
	{
		LogString msg = helpers::Exception::makeMessage(LOG4CXX_STR("apr_file_open"), stat);
		msg += LOG4CXX_STR(". Check the privilege or try to remove [");
		helpers::Transcoder::decode(m_priv->_mapFileName, msg);
		msg += LOG4CXX_STR("] if it exists.");
		LogLog::warn(msg);
		return -1;
	}

	if (isMapFileEmpty(pool))
	{
		stat = apr_file_trunc(m_priv->_file_map, MAX_FILE_LEN + 1);

		if (stat != APR_SUCCESS)
		{
			LogLog::warn(helpers::Exception::makeMessage(LOG4CXX_STR("apr_file_trunc"), stat));
			apr_file_close(m_priv->_file_map);
			return -1;
		}
	}

	stat = apr_mmap_create(&m_priv->_mmap, m_priv->_file_map, 0, MAX_FILE_LEN, APR_MMAP_WRITE | APR_MMAP_READ, m_priv->_mmapPool.getAPRPool());

	if (stat != APR_SUCCESS)
	{
		LogLog::warn(helpers::Exception::makeMessage(LOG4CXX_STR("apr_mmap_create"), stat));
		apr_file_close(m_priv->_file_map);
		return -1;
	}

	return 0;
}

int TimeBasedRollingPolicy::lockMMapFile(int type)
{
	apr_status_t stat = apr_file_lock(m_priv->_lock_file, type);

	if (stat != APR_SUCCESS)
	{
		LogLog::warn(helpers::Exception::makeMessage(LOG4CXX_STR("apr_file_lock for mmap"), stat));
	}

	return stat;
}

int TimeBasedRollingPolicy::unLockMMapFile()
{
	apr_status_t stat = apr_file_unlock(m_priv->_lock_file);

	if (stat != APR_SUCCESS)
	{
		LogLog::warn(helpers::Exception::makeMessage(LOG4CXX_STR("apr_file_unlock for mmap"), stat));
	}

	return stat;
}
#else
int TimeBasedRollingPolicy::createMMapFile(const std::string&, LOG4CXX_NS::helpers::Pool&) {
	return 0;
}

bool TimeBasedRollingPolicy::isMapFileEmpty(LOG4CXX_NS::helpers::Pool&){
	return true;
}

void TimeBasedRollingPolicy::initMMapFile(const LogString&, LOG4CXX_NS::helpers::Pool&){}

int TimeBasedRollingPolicy::lockMMapFile(int){
	return 0;
}

int TimeBasedRollingPolicy::unLockMMapFile(){
	return 0;
}

const std::string TimeBasedRollingPolicy::createFile(const std::string&, const std::string&, LOG4CXX_NS::helpers::Pool&){
	return "";
}
#endif

TimeBasedRollingPolicy::TimeBasedRollingPolicy() :
	m_priv(std::make_unique<TimeBasedRollingPolicyPrivate>())
{
}

TimeBasedRollingPolicy::~TimeBasedRollingPolicy(){}

void TimeBasedRollingPolicy::activateOptions(LOG4CXX_NS::helpers::Pool& pool)
{
	// find out period from the filename pattern
	if (getFileNamePattern().length() > 0)
	{
		parseFileNamePattern();
	}
	else
	{
		LogLog::warn(
			LOG4CXX_STR("The FileNamePattern option must be set before using TimeBasedRollingPolicy. "));
		throw IllegalStateException();
	}

	PatternConverterPtr dtc(getDatePatternConverter());

	if (dtc == NULL)
	{
		throw NullPointerException(LOG4CXX_STR("DatePatternConverter"));
	}

	LogString buf;
	ObjectPtr obj = std::make_shared<Date>();
	formatFileName(obj, buf, pool);
	m_priv->lastFileName = buf;

	m_priv->suffixLength = 0;

	if (m_priv->lastFileName.length() >= 3)
	{
		if (m_priv->lastFileName.compare(m_priv->lastFileName.length() - 3, 3, LOG4CXX_STR(".gz")) == 0)
		{
			m_priv->suffixLength = 3;
		}
		else if (m_priv->lastFileName.length() >= 4 && m_priv->lastFileName.compare(m_priv->lastFileName.length() - 4, 4, LOG4CXX_STR(".zip")) == 0)
		{
			m_priv->suffixLength = 4;
		}
	}
}


#define RULES_PUT(spec, cls) \
	specs.insert(PatternMap::value_type(LogString(LOG4CXX_STR(spec)), (PatternConstructor) cls ::newInstance))

LOG4CXX_NS::pattern::PatternMap TimeBasedRollingPolicy::getFormatSpecifiers() const
{
	PatternMap specs;
	RULES_PUT("d", FileDatePatternConverter);
	RULES_PUT("date", FileDatePatternConverter);
	return specs;
}

/**
 * {@inheritDoc}
 */
RolloverDescriptionPtr TimeBasedRollingPolicy::initialize(
	const   LogString&  currentActiveFile,
	const   bool        append,
	Pool&       pool)
{
	Date now;
	log4cxx_time_t n = now.getTime();
	m_priv->nextCheck = now.getNextSecond();

	File currentFile(currentActiveFile);

	LogString buf;
	ObjectPtr obj = std::make_shared<Date>(currentFile.exists(pool) ? currentFile.lastModified(pool) : n);
	formatFileName(obj, buf, pool);
	m_priv->lastFileName = buf;

	ActionPtr noAction;

	if (currentActiveFile.length() > 0)
	{
		return std::make_shared<RolloverDescription>(
					currentActiveFile, append, noAction, noAction);
	}
	else
	{
		m_priv->bRefreshCurFile = true;
		return std::make_shared<RolloverDescription>(
					m_priv->lastFileName.substr(0, m_priv->lastFileName.length() - m_priv->suffixLength), append,
					noAction, noAction);
	}
}

RolloverDescriptionPtr TimeBasedRollingPolicy::rollover(
	const   LogString&  currentActiveFile,
	const   bool        append,
	Pool&       pool)
{
	Date now;
	log4cxx_time_t n = now.getTime();
	m_priv->nextCheck = now.getNextSecond();

	LogString buf;
	ObjectPtr obj = std::make_shared<Date>(n);
	formatFileName(obj, buf, pool);

	LogString newFileName(buf);

	if( m_priv->multiprocess ){
#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER

		if (!m_priv->bAlreadyInitialized)
		{
			if (getPatternConverterList().size())
			{
				(*(getPatternConverterList().begin()))->format(obj, m_priv->_fileNamePattern, pool);
			}
			else
			{
				m_priv->_fileNamePattern = m_priv->lastFileName;
			}

			if (!m_priv->_lock_file)
			{
				LOG4CXX_ENCODE_CHAR(mapFile, m_priv->_fileNamePattern);
				const std::string lockname = createFile(mapFile, LOCK_FILE_SUFFIX, m_priv->_mmapPool);
				apr_status_t stat = apr_file_open(&m_priv->_lock_file, lockname.c_str(), APR_CREATE | APR_READ | APR_WRITE, APR_OS_DEFAULT, m_priv->_mmapPool.getAPRPool());

				if (stat != APR_SUCCESS)
				{
					LOG4CXX_DECODE_CHAR(msg, lockname);
					msg += LOG4CXX_STR(": apr_file_open");
					LogLog::warn(helpers::Exception::makeMessage(msg, stat));
				}
			}

			initMMapFile(m_priv->lastFileName, m_priv->_mmapPool);
		}
		m_priv->bAlreadyInitialized = true;

		if (m_priv->_mmap && !isMapFileEmpty(m_priv->_mmapPool))
		{
			lockMMapFile(APR_FLOCK_SHARED);
			LogString mapLastFile(static_cast<logchar*>(m_priv->_mmap->mm));
			m_priv->lastFileName = mapLastFile;
			unLockMMapFile();
		}
		else
		{
			m_priv->_mmap = NULL;
			initMMapFile(m_priv->lastFileName, m_priv->_mmapPool);
		}
#endif
	}

	//
	//  if file names haven't changed, no rollover
	//
	if (newFileName == m_priv->lastFileName)
	{
		RolloverDescriptionPtr desc;
		return desc;
	}

	ActionPtr renameAction;
	ActionPtr compressAction;
	LogString lastBaseName(
		m_priv->lastFileName.substr(0, m_priv->lastFileName.length() - m_priv->suffixLength));
	LogString nextActiveFile(
		newFileName.substr(0, newFileName.length() - m_priv->suffixLength));

	if(getCreateIntermediateDirectories()){
		File compressedFile(m_priv->lastFileName);
		File compressedParent (compressedFile.getParent(pool));
		compressedParent.mkdirs(pool);
	}

	//
	//   if currentActiveFile is not lastBaseName then
	//        active file name is not following file pattern
	//        and requires a rename plus maintaining the same name
	if (currentActiveFile != lastBaseName)
	{
		renameAction = std::make_shared<FileRenameAction>(
					File().setPath(currentActiveFile), File().setPath(lastBaseName), true);
		nextActiveFile = currentActiveFile;
	}

	if (m_priv->suffixLength == 3)
	{
		GZCompressActionPtr comp = std::make_shared<GZCompressAction>(
					File().setPath(lastBaseName), File().setPath(m_priv->lastFileName), true);
		comp->setThrowIOExceptionOnForkFailure(m_priv->throwIOExceptionOnForkFailure);
		compressAction = comp;
	}

	if (m_priv->suffixLength == 4)
	{
		ZipCompressActionPtr comp = std::make_shared<ZipCompressAction>(
					File().setPath(lastBaseName), File().setPath(m_priv->lastFileName), true);
		comp->setThrowIOExceptionOnForkFailure(m_priv->throwIOExceptionOnForkFailure);
		compressAction = comp;
	}

	if( m_priv->multiprocess ){
#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
		size_t byteCount = sizeof (logchar) * newFileName.size();
		if (MAX_FILE_LEN - sizeof (logchar) < byteCount)
		{
			LogString msg(newFileName + LOG4CXX_STR(": cannot exceed "));
			StringHelper::toString(MAX_FILE_LEN / sizeof (logchar), pool, msg);
			msg += LOG4CXX_STR(" characters");
			throw IllegalArgumentException(msg);
		}
		if (m_priv->_mmap && !isMapFileEmpty(m_priv->_mmapPool))
		{
			lockMMapFile(APR_FLOCK_EXCLUSIVE);
			memset(m_priv->_mmap->mm, 0, MAX_FILE_LEN);
			memcpy(m_priv->_mmap->mm, newFileName.c_str(), byteCount);
			unLockMMapFile();
		}
		else
		{
			m_priv->_mmap = NULL;
			initMMapFile(newFileName, m_priv->_mmapPool);
		}
#endif
	}else{
		m_priv->lastFileName = newFileName;
	}

	return std::make_shared<RolloverDescription>(nextActiveFile, append, renameAction, compressAction);
}

bool TimeBasedRollingPolicy::isTriggeringEvent(
	Appender* appender,
	const LOG4CXX_NS::spi::LoggingEventPtr& /* event */,
	const LogString&  filename,
	size_t /* fileLength */)
{
	if( m_priv->multiprocess ){
#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
		if (m_priv->bRefreshCurFile && m_priv->_mmap && !isMapFileEmpty(m_priv->_mmapPool))
		{
			lockMMapFile(APR_FLOCK_SHARED);
			LogString mapCurrent(static_cast<logchar*>(m_priv->_mmap->mm));
			unLockMMapFile();
			LogString mapCurrentBase(mapCurrent.substr(0, mapCurrent.length() - m_priv->suffixLength));

			if (!mapCurrentBase.empty() && mapCurrentBase != filename)
			{
				if (auto fappend = dynamic_cast<FileAppender*>(appender))
					fappend->setFile(mapCurrentBase);
			}
		}

		return ( Date::currentTime() > m_priv->nextCheck) || (!m_priv->bAlreadyInitialized);
#endif
	}

	return Date::currentTime() > m_priv->nextCheck;
}

void TimeBasedRollingPolicy::setMultiprocess(bool multiprocess){
#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
	// If we don't have the multiprocess stuff, disregard any attempt to set this value
	m_priv->multiprocess = multiprocess;
#endif
}

void TimeBasedRollingPolicy::setOption(const LogString& option,
	const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("THROWIOEXCEPTIONONFORKFAILURE"),
			LOG4CXX_STR("throwioexceptiononforkfailure")))
	{
		m_priv->throwIOExceptionOnForkFailure = OptionConverter::toBoolean(value, true);
	}
	else
	{
		RollingPolicyBase::setOption(option, value);
	}
}

/**
 * Was the name in shared memory set by this process?
 */
bool TimeBasedRollingPolicy::isLastFileNameUnchanged()
{
	bool result = true;
	if( m_priv->multiprocess ){
#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
		if (m_priv->_mmap)
		{
			lockMMapFile(APR_FLOCK_SHARED);
			LogString mapCurrent(static_cast<logchar*>(m_priv->_mmap->mm));
			unLockMMapFile();
			result = (mapCurrent == m_priv->lastFileName);
		}
#endif
	}
	return result;
}

/**
 * Load the name (set by some other process) from shared memory
 */
void TimeBasedRollingPolicy::loadLastFileName()
{
	if( m_priv->multiprocess ){
#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
		if (m_priv->_mmap)
		{
			lockMMapFile(APR_FLOCK_SHARED);
			LogString mapLastFile(static_cast<logchar*>(m_priv->_mmap->mm));
			unLockMMapFile();
			if (!mapLastFile.empty())
				m_priv->lastFileName = mapLastFile;
		}
#endif
	}
}
