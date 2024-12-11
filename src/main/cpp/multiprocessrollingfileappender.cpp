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
#include <log4cxx/rolling/fixedwindowrollingpolicy.h>
#include <log4cxx/rolling/manualtriggeringpolicy.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/private/rollingfileappender_priv.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>
#include <mutex>

namespace LOG4CXX_NS
{

using namespace helpers;

namespace rolling
{
/**
 * Wrapper for OutputStream that will report all log file
 * size changes back to the appender for file length calculations.
 */
class MultiprocessOutputStream : public OutputStream
{
	/**
	 * Wrapped output stream.
	 */
private:
	OutputStreamPtr os;

	/**
	 * Rolling file appender to inform of stream writes.
	 */
	MultiprocessRollingFileAppender* rfa;

public:
	/**
	 * Constructor.
	 * @param os output stream to wrap.
	 * @param rfa rolling file appender to inform.
	 */
	MultiprocessOutputStream(const OutputStreamPtr& os1, MultiprocessRollingFileAppender* rfa1)
		: os(os1), rfa(rfa1)
	{
	}

	/**
	 * {@inheritDoc}
	 */
	void close(Pool& p) override
	{
		os->close(p);
		rfa = 0;
	}

	/**
	 * {@inheritDoc}
	 */
	void flush(Pool& p) override
	{
		os->flush(p);
	}

	/**
	 * {@inheritDoc}
	 */
	void write(ByteBuffer& buf, Pool& p) override
	{
		os->write(buf, p);

		if (rfa != 0)
		{
			rfa->setFileLength(File().setPath(rfa->getFile()).length(p));
		}
	}

	static FileOutputStreamPtr getFileOutputStream(const WriterPtr& writer)
	{
		FileOutputStreamPtr result;
		auto osw = LOG4CXX_NS::cast<OutputStreamWriter>(writer);
		if( !osw ){
			LogLog::error( LOG4CXX_STR("Can't cast writer to OutputStreamWriter") );
			return result;
		}
		auto cos = LOG4CXX_NS::cast<MultiprocessOutputStream>(osw->getOutputStreamPtr());
		if( !cos ){
			LogLog::error( LOG4CXX_STR("Can't cast stream to MultiprocessOutputStream") );
			return result;
		}
		result = LOG4CXX_NS::cast<FileOutputStream>(cos->os);
		if( !result ){
			LogLog::error( LOG4CXX_STR("Can't cast stream to FileOutputStream") );
		}
		return result;
	}
};
} // namespace rolling
} // namespace LOG4CXX_NS

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::rolling;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;

#define _priv static_cast<RollingFileAppenderPriv*>(m_priv.get())

IMPLEMENT_LOG4CXX_OBJECT(MultiprocessRollingFileAppender)

/**
 * Construct a new instance.
 */
MultiprocessRollingFileAppender::MultiprocessRollingFileAppender()
{
}

void MultiprocessRollingFileAppender::releaseFileLock(apr_file_t* lock_file)
{
	if (lock_file)
	{
		apr_status_t stat = apr_file_unlock(lock_file);

		if (stat != APR_SUCCESS)
		{
			LogLog::warn(LOG4CXX_STR("flock: unlock failed"));
		}

		apr_file_close(lock_file);
		lock_file = NULL;
	}
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
	return rolloverInternal(p);
}

bool MultiprocessRollingFileAppender::rolloverInternal(Pool& p)
{
	//
	//   can't roll without a policy
	//
	if (_priv->rollingPolicy != NULL)
	{

		if (auto pTimeBased = LOG4CXX_NS::cast<TimeBasedRollingPolicy>(_priv->rollingPolicy))
			pTimeBased->setMultiprocess(true);

		{
			LogString fileName(getFile());
			RollingPolicyBasePtr basePolicy = LOG4CXX_NS::cast<RollingPolicyBase>(_priv->rollingPolicy);
			apr_time_t n = apr_time_now();
			ObjectPtr obj = std::make_shared<Date>(n);
			LogString fileNamePattern;

			if (basePolicy)
			{
				if (basePolicy->getPatternConverterList().size())
				{
					(*(basePolicy->getPatternConverterList().begin()))->format(obj, fileNamePattern, p);
					fileName = std::string(fileNamePattern);
				}
			}

			bool bAlreadyRolled = true;

			LogString lockname = fileName + ".lock";
			apr_file_t* lock_file;
			auto stat = apr_file_open(&lock_file, lockname.c_str(), APR_CREATE | APR_READ | APR_WRITE, APR_OS_DEFAULT, p.getAPRPool());

			if (stat != APR_SUCCESS)
			{
				LogString err = lockname + LOG4CXX_STR(": apr_file_open error: ");
				err += (strerror(errno));
				LogLog::warn(err);
				bAlreadyRolled = false;
				lock_file = NULL;
			}
			else
			{
				stat = apr_file_lock(lock_file, APR_FLOCK_EXCLUSIVE);

				if (stat != APR_SUCCESS)
				{
					LogString err = lockname + LOG4CXX_STR(": apr_file_lock error: ");
					err += (strerror(errno));
					LogLog::warn(err);
					bAlreadyRolled = false;
				}
				else
				{
					if (_priv->_event)
					{
						_priv->triggeringPolicy->isTriggeringEvent(this, _priv->_event, getFile(), getFileLength());
					}
				}
			}

			if (bAlreadyRolled)
			{
				auto fos = MultiprocessOutputStream::getFileOutputStream(getWriter());
				if( !fos )
					return false;
				apr_finfo_t finfo1;
				apr_status_t st1 = apr_file_info_get(&finfo1, APR_FINFO_IDENT, fos->getFilePtr());

				if (st1 != APR_SUCCESS)
				{
					LogLog::warn(LOG4CXX_STR("apr_file_info_get failed"));
				}

				LogString fname = getFile();
				apr_finfo_t finfo2;
				apr_status_t st2 = apr_stat(&finfo2, fname.c_str(), APR_FINFO_IDENT, p.getAPRPool());

				if (st2 != APR_SUCCESS)
				{
					LogLog::warn(fname + LOG4CXX_STR(": apr_stat failed."));
				}

				bAlreadyRolled = ((st1 == APR_SUCCESS) && (st2 == APR_SUCCESS)
						&& ((finfo1.device != finfo2.device) || (finfo1.inode != finfo2.inode)));
			}

			if (!bAlreadyRolled)
			{

				try
				{
					if (auto rollover1 = _priv->rollingPolicy->rollover(this->getFile(), this->getAppend(), p))
					{
						if (rollover1->getActiveFileName() == getFile())
						{
							closeWriter();

							bool success = true;

							if (auto pAction = rollover1->getSynchronous())
							{
								success = pAction->execute(p);
							}

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
										msg.append(getFile());
										msg.append(LOG4CXX_STR("] failed"));
										_priv->errorHandler->error(msg, ex, 0);
									}
								}
							}
							else
							{
								LogString msg(LOG4CXX_STR("Rollover of ["));
								msg.append(getFile());
								msg.append(LOG4CXX_STR("] failed"));
								_priv->errorHandler->error(msg);
							}
							setFileInternal(rollover1->getActiveFileName(), appendToExisting, _priv->bufferedIO, _priv->bufferSize, p);
						}
						else
						{
							closeWriter();
							setFileInternal(rollover1->getActiveFileName());
							// Call activateOptions to create any intermediate directories(if required)
							FileAppender::activateOptionsInternal(p);
							OutputStreamPtr os = std::make_shared<FileOutputStream>
								( rollover1->getActiveFileName()
								, rollover1->getAppend()
								);
							setWriterInternal(createWriter(os));

							bool success = true;

							if (auto pAction = rollover1->getSynchronous())
							{
								success = false;

								try
								{
									success = pAction->execute(p);
								}
								catch (std::exception& ex)
								{
									LogString msg(LOG4CXX_STR("Rollover of ["));
									msg.append(getFile());
									msg.append(LOG4CXX_STR("] failed"));
									_priv->errorHandler->error(msg, ex, 0);
								}
							}

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

								//
								//   async action not yet implemented
								//
								if (auto asyncAction = rollover1->getAsynchronous())
								{
									asyncAction->execute(p);
								}
							}

							writeHeader(p);
						}

						releaseFileLock(lock_file);
						return true;
					}
				}
				catch (std::exception& ex)
				{
					LogString msg(LOG4CXX_STR("Rollover of ["));
					msg.append(getFile());
					msg.append(LOG4CXX_STR("] failed"));
					_priv->errorHandler->error(msg, ex, 0);
				}

			}
			else
			{
				reopenLatestFile(p);
			}

			releaseFileLock(lock_file);
		}
	}

	return false;
}

/**
 * re-open current file when its own handler has been renamed
 */
void MultiprocessRollingFileAppender::reopenLatestFile(Pool& p)
{
	closeWriter();
	OutputStreamPtr os = std::make_shared<FileOutputStream>(getFile(), true);
	WriterPtr newWriter(createWriter(os));
	setFile(getFile());
	setWriter(newWriter);
	_priv->fileLength = File().setPath(getFile()).length(p);
	writeHeader(p);
}


/**
 * {@inheritDoc}
*/
void MultiprocessRollingFileAppender::subAppend(const LoggingEventPtr& event, Pool& p)
{
	// The rollover check must precede actual writing. This is the
	// only correct behavior for time driven triggers.
	if (
		_priv->triggeringPolicy->isTriggeringEvent(
			this, event, getFile(), getFileLength()))
	{
		//
		//   wrap rollover request in try block since
		//    rollover may fail in case read access to directory
		//    is not provided.  However appender should still be in good
		//     condition and the append should still happen.
		try
		{
			_priv->_event = event;
			rolloverInternal(p);
		}
		catch (std::exception& ex)
		{
			LogString msg(LOG4CXX_STR("Rollover of ["));
			msg.append(getFile());
			msg.append(LOG4CXX_STR("] failed"));
			_priv->errorHandler->error(msg, ex, 0);
		}
	}

	auto fos = MultiprocessOutputStream::getFileOutputStream(getWriter());
	if( !fos )
		return;

	// check for a file rolloover before every write
	//
	apr_finfo_t finfo1;
	apr_status_t st1 = apr_file_info_get(&finfo1, APR_FINFO_IDENT, fos->getFilePtr());

	if (st1 != APR_SUCCESS)
	{
		LogLog::warn(LOG4CXX_STR("apr_file_info_get failed"));
	}

	LogString fname = getFile();
	apr_finfo_t finfo2;
	apr_status_t st2 = apr_stat(&finfo2, fname.c_str(), APR_FINFO_IDENT, p.getAPRPool());

	if (st2 != APR_SUCCESS)
	{
		LogLog::warn(fname + LOG4CXX_STR(": apr_stat failed."));
	}

	bool bAlreadyRolled = ((st1 == APR_SUCCESS) && (st2 == APR_SUCCESS)
			&& ((finfo1.device != finfo2.device) || (finfo1.inode != finfo2.inode)));

	if (bAlreadyRolled)
	{
		reopenLatestFile(p);
	}

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
	OutputStreamPtr cos = std::make_shared<MultiprocessOutputStream>(os, this);
	return FileAppender::createWriter(cos);
}


void MultiprocessRollingFileAppender::setFileLength(size_t length)
{
	_priv->fileLength = length;
}
