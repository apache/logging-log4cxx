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

#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/rolling/rolloverdescription.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/rolling/fixedwindowrollingpolicy.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>
#include <log4cxx/rolling/sizebasedtriggeringpolicy.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/private/rollingfileappender_priv.h>
#include <mutex>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::rolling;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;

#define _priv static_cast<RollingFileAppenderPriv*>(m_priv.get())

IMPLEMENT_LOG4CXX_OBJECT(RollingFileAppender)


/**
 * Construct a new instance.
 */
RollingFileAppender::RollingFileAppender()
	: FileAppender(std::make_unique<RollingFileAppenderPriv>())
{
}

RollingFileAppender::RollingFileAppender( std::unique_ptr<RollingFileAppenderPriv> priv )
	: FileAppender(std::move(priv))
{
}

void RollingFileAppender::setOption(const LogString& option, const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("MAXFILESIZE"), LOG4CXX_STR("maxfilesize"))
		|| StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("MAXIMUMFILESIZE"), LOG4CXX_STR("maximumfilesize")))
	{
		setMaxFileSize(value);
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("MAXBACKUPINDEX"), LOG4CXX_STR("maxbackupindex"))
		|| StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("MAXIMUMBACKUPINDEX"), LOG4CXX_STR("maximumbackupindex")))
	{
		setMaxBackupIndex(StringHelper::toInt(value));
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("FILEDATEPATTERN"), LOG4CXX_STR("filedatepattern")))
	{
		setDatePattern(value);
	}
	else
	{
		FileAppender::setOption(option, value);
	}
}

int RollingFileAppender::getMaxBackupIndex() const
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	int result = 1;
	if (auto fwrp = LOG4CXX_NS::cast<FixedWindowRollingPolicy>(_priv->rollingPolicy))
		result = fwrp->getMaxIndex();
	return result;
}

void RollingFileAppender::setMaxBackupIndex(int maxBackups)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	auto fwrp = LOG4CXX_NS::cast<FixedWindowRollingPolicy>(_priv->rollingPolicy);
	if (!fwrp)
	{
		fwrp = std::make_shared<FixedWindowRollingPolicy>();
		fwrp->setFileNamePattern(getFile() + LOG4CXX_STR(".%i"));
		_priv->rollingPolicy = fwrp;
	}
	fwrp->setMaxIndex(maxBackups);
}

size_t RollingFileAppender::getMaximumFileSize() const
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	size_t result = 10 * 1024 * 1024;
	if (auto sbtp = LOG4CXX_NS::cast<SizeBasedTriggeringPolicy>(_priv->triggeringPolicy))
		result = sbtp->getMaxFileSize();
	return result;
}

void RollingFileAppender::setMaximumFileSize(size_t maxFileSize)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	auto sbtp = LOG4CXX_NS::cast<SizeBasedTriggeringPolicy>(_priv->triggeringPolicy);
	if (!sbtp)
	{
		sbtp = std::make_shared<SizeBasedTriggeringPolicy>();
		_priv->triggeringPolicy = sbtp;
	}
	sbtp->setMaxFileSize(maxFileSize);
}

void RollingFileAppender::setMaxFileSize(const LogString& value)
{
	setMaximumFileSize(OptionConverter::toFileSize(value, long(getMaximumFileSize() + 1)));
}

LogString RollingFileAppender::makeFileNamePattern(const LogString& datePattern)
{
	LogString result(getFile());
	bool inLiteral = false;
	bool inPattern = false;

	for (size_t i = 0; i < datePattern.length(); i++)
	{
		if (datePattern[i] == 0x27 /* '\'' */)
		{
			inLiteral = !inLiteral;

			if (inLiteral && inPattern)
			{
				result.append(1, (logchar) 0x7D /* '}' */);
				inPattern = false;
			}
		}
		else
		{
			if (!inLiteral && !inPattern)
			{
				const logchar dbrace[] = { 0x25, 0x64, 0x7B, 0 }; // "%d{"
				result.append(dbrace);
				inPattern = true;
			}

			result.append(1, datePattern[i]);
		}
	}

	if (inPattern)
	{
		result.append(1, (logchar) 0x7D /* '}' */);
	}
	return result;
}

void RollingFileAppender::setDatePattern(const LogString& newPattern)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	auto tbrp = LOG4CXX_NS::cast<TimeBasedRollingPolicy>(_priv->rollingPolicy);
	if (!tbrp)
	{
		tbrp = std::make_shared<TimeBasedRollingPolicy>();
		_priv->rollingPolicy = tbrp;
	}
	tbrp->setFileNamePattern(makeFileNamePattern(newPattern));
}

/**
 * Prepare instance of use.
 */
void RollingFileAppender::activateOptions(  )
{
	if (_priv->activateOptions())
	{
		_priv->activate();
	}
}

bool RollingFileAppender::RollingFileAppenderPriv::activateOptions()
{
	bool result = false;
	if (!this->rollingPolicy)
	{
		LogLog::warn(LOG4CXX_STR("No rolling policy configured for the appender named [")
			+ this->name + LOG4CXX_STR("]."));
		auto fwrp = std::make_shared<FixedWindowRollingPolicy>();
		fwrp->setFileNamePattern(this->targetFile.getPath() + LOG4CXX_STR(".%i"));
		this->rollingPolicy = fwrp;
	}
	else if (auto fwrp = LOG4CXX_NS::cast<FixedWindowRollingPolicy>(this->rollingPolicy))
	{
		// Was fwrp created to store the maximum index before the file name was set?
		if (fwrp->getFileNamePattern() == LOG4CXX_STR(".%i"))
			fwrp->setFileNamePattern(this->targetFile.getPath() + LOG4CXX_STR(".%i"));
	}

	//
	//  if no explicit triggering policy and rolling policy is both.
	//
	if (!this->triggeringPolicy)
	{
		TriggeringPolicyPtr trig = LOG4CXX_NS::cast<TriggeringPolicy>(this->rollingPolicy);

		if (trig != NULL)
		{
			this->triggeringPolicy = trig;
		}
	}

	if (!this->triggeringPolicy)
	{
		LogLog::warn(LOG4CXX_STR("No triggering policy configured for the appender named [")
			+ this->name + LOG4CXX_STR("]."));
		this->triggeringPolicy = std::make_shared<SizeBasedTriggeringPolicy>();
	}

	std::lock_guard<std::recursive_mutex> lock(this->mutex);
	this->triggeringPolicy->activateOptions();
	this->rollingPolicy->activateOptions();

	try
	{
		if (auto policy = this->rollingPolicy->initialize(this->targetFile.getPath(), this->fileAppend))
		{
			if (auto syncAction = policy->getSynchronous())
			{
				syncAction->execute();
			}

			this->targetFile.setPath(policy->getActiveFileName());
			this->fileAppend = policy->getAppend();

			//
			//  async action not yet implemented
			//
			if (auto asyncAction = policy->getAsynchronous())
			{
				asyncAction->execute();
			}
		}

		if (this->fileAppend)
		{
			this->fileLength = this->targetFile.length();
		}
		else
		{
			this->fileLength = 0;
		}

		result = true;
	}
	catch (std::exception& ex)
	{
		LogLog::warn(LOG4CXX_STR("Exception activating RollingFileAppender ") + this->targetFile.getPath(), ex);
	}
	return result;
}

bool RollingFileAppender::rollover()
{
	bool result = false;
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	if (_priv->rollingPolicy)
		result = _priv->rollover(getFile(), getAppend());
	return result;
}

bool RollingFileAppender::RollingFileAppenderPriv::rollover(const LogString& fileName, bool append)
{
	bool result = false;
	auto policy = this->rollingPolicy->rollover(fileName, append);
	if (policy)
	{
		if (policy->getActiveFileName() == fileName)
			result = this->namePreservingRollover(policy, fileName);
		else
			result = this->nameEvolvingRollover(policy, fileName);
	}
	return result;
}

bool RollingFileAppender::RollingFileAppenderPriv::namePreservingRollover
	( const RolloverDescriptionPtr& policy
	, const LogString&              fileName
	)
{
	this->close();

	bool result = true;
	if (auto action = policy->getSynchronous())
	{
		result = false;
		try
		{
			result = action->execute();
		}
		catch (std::exception& ex)
		{
			LogString msg(LOG4CXX_STR("Rollover of ["));
			msg.append(fileName);
			msg.append(LOG4CXX_STR("] failed"));
			this->errorHandler->error(msg, ex, 0);
		}
	}

	bool appendToExisting = true;
	if (result)
	{
		appendToExisting = policy->getAppend();
		if (appendToExisting)
		{
			this->fileLength = File(policy->getActiveFileName()).length();
		}
		else
		{
			this->fileLength = 0;
		}

		if (auto asyncAction = policy->getAsynchronous())
		{
			try
			{
				asyncAction->execute();
			}
			catch (std::exception& ex)
			{
				LogString msg(LOG4CXX_STR("Rollover of ["));
				msg.append(fileName);
				msg.append(LOG4CXX_STR("] failed"));
				this->errorHandler->error(msg, ex, 0);
			}
		}
	}
	this->targetFile.setPath(policy->getActiveFileName());
	this->fileAppend = appendToExisting;
	this->activate();
	if (result)
		this->writeHeader();
	return result;
}

bool RollingFileAppender::RollingFileAppenderPriv::nameEvolvingRollover
	( const RolloverDescriptionPtr& policy
	, const LogString&              fileName
	)
{
	this->targetFile.setPath(policy->getActiveFileName());
	this->fileAppend = policy->getAppend();
	this->activate();
	this->writeHeader();

	bool result = true;
	if (auto action = policy->getSynchronous())
	{
		result = false;
		try
		{
			result = action->execute();
		}
		catch (std::exception& ex)
		{
			LogString msg(LOG4CXX_STR("Rollover of ["));
			msg.append(fileName);
			msg.append(LOG4CXX_STR("] failed"));
			this->errorHandler->error(msg, ex, 0);
		}
	}

	if (result)
	{
		if (policy->getAppend())
		{
			this->fileLength = File().setPath(policy->getActiveFileName()).length();
		}
		else
		{
			this->fileLength = 0;
		}

		if (auto asyncAction = policy->getAsynchronous())
		{
			asyncAction->execute();
		}
	}
	return result;
}

void RollingFileAppender::subAppend( const spi::LoggingEventPtr& event )
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
			_priv->rollover(getFile(), getAppend());
		}
		catch (std::exception& ex)
		{
			LogString msg(LOG4CXX_STR("Rollover of ["));
			msg.append(getFile());
			msg.append(LOG4CXX_STR("] failed"));
			_priv->errorHandler->error(msg, ex, 0);
		}
	}

	FileAppender::subAppend( event );
}

/**
 * TThe policy that implements the scheme for rolling over a log file.
 */
RollingPolicyPtr RollingFileAppender::getRollingPolicy() const
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	return _priv->rollingPolicy;
}

/**
 * The policy that determine when to trigger a log file rollover.
 */
TriggeringPolicyPtr RollingFileAppender::getTriggeringPolicy() const
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	return _priv->triggeringPolicy;
}

/**
 * Set the scheme for rolling over log files.
 */
void RollingFileAppender::setRollingPolicy(const RollingPolicyPtr& policy)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	_priv->rollingPolicy = policy;
}

/**
 * Set policy that determine when to trigger a log file rollover.
 */
void RollingFileAppender::setTriggeringPolicy(const TriggeringPolicyPtr& policy)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	_priv->triggeringPolicy = policy;
}

/**
 * Close appender.  Waits for any asynchronous file compression actions to be completed.
 */
void RollingFileAppender::close()
{
	FileAppender::close();
}

namespace LOG4CXX_NS
{
namespace rolling
{
/**
 * Wrapper for OutputStream that will report all write
 * operations back to this class for file length calculations.
 */
class RollingFileAppender::RollingFileAppenderPriv::CountingOutputStream : public OutputStream
{
		/**
		 * Wrapped output stream.
		 */
	private:
		OutputStreamPtr os;

		/**
		 * Rolling file appender to inform of stream writes.
		 */
		RollingFileAppenderPriv* parent;

	public:
		/**
		 * Constructor.
		 * @param os output stream to wrap.
		 * @param parent rolling file appender to inform.
		 */
		CountingOutputStream
			( const OutputStreamPtr& os1
			, RollingFileAppender::RollingFileAppenderPriv* parent1
			)
			: os(os1)
			, parent(parent1)
		{
		}

		/**
		 * {@inheritDoc}
		 */
		void close(  ) override
		{
			os->close();
			parent = 0;
		}

		/**
		 * {@inheritDoc}
		 */
		void flush(  ) override
		{
			os->flush();
		}

		/**
		 * {@inheritDoc}
		 */
		void write( ByteBuffer& buf ) override
		{
			os->write(buf);

			if (parent != 0)
			{
				parent->fileLength += buf.limit();
			}
		}
};
}
}

WriterPtr RollingFileAppender::RollingFileAppenderPriv::createWriter(const OutputStreamPtr& os)
{
	OutputStreamPtr cos = std::make_shared<CountingOutputStream>(os, this);
	return FileAppenderPriv::createWriter(cos);
}

/**
 * Get byte length of current active log file.
 * @return byte length of current active log file.
 */
size_t RollingFileAppender::getFileLength() const
{
	return _priv->fileLength;
}

