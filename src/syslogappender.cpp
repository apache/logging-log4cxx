/***************************************************************************
                          syslogappender.cpp  -  class SysLogAppender
                             -------------------
    begin                : 2003/08/05
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/net/syslogappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/datagramsocket.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/level.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;

IMPLEMENT_LOG4CXX_OBJECT(SyslogAppender)

SyslogAppender::SyslogAppender()
: syslogFacility(LOG_USER), facilityPrinting(false), sw(0)
{
	this->initSyslogFacilityStr();
}

SyslogAppender::SyslogAppender(LayoutPtr layout,
	SyslogAppender::SyslogFacility syslogFacility)
: syslogFacility(syslogFacility), facilityPrinting(false), sw(0)
{
	this->layout = layout;
	this->initSyslogFacilityStr();
}

SyslogAppender::SyslogAppender(LayoutPtr layout,
	const String& syslogHost, SyslogAppender::SyslogFacility syslogFacility)
: syslogFacility(syslogFacility), facilityPrinting(false), sw(0)
{
	this->layout = layout;
	this->initSyslogFacilityStr();
	setSyslogHost(syslogHost);
}

SyslogAppender::~SyslogAppender()
{
	finalize();
}

/** Release any resources held by this SyslogAppender.*/
void SyslogAppender::close()
{
	closed = true;
	if (sw != 0)
	{
		delete sw;
		sw = 0;
	}
}

void SyslogAppender::initSyslogFacilityStr()
{
	facilityStr = getFacilityString(this->syslogFacility);

	if (facilityStr.empty())
	{
		LOGLOG_ERROR(_T("\"") << syslogFacility <<
					_T("\" is an unknown syslog facility. Defaulting to \"USER\"."));
		this->syslogFacility = LOG_USER;
		facilityStr = _T("user:");
	}
	else
	{
		facilityStr += _T(":");
	}
}

/**
Returns the specified syslog facility as a lower-case String,
e.g. "kern", "user", etc.
*/
String SyslogAppender::getFacilityString(
	SyslogAppender::SyslogFacility syslogFacility)
{
	switch(syslogFacility)
	{
	case LOG_KERN:      return _T("kern");
	case LOG_USER:      return _T("user");
	case LOG_MAIL:      return _T("mail");
	case LOG_DAEMON:    return _T("daemon");
	case LOG_AUTH:      return _T("auth");
	case LOG_SYSLOG:    return _T("syslog");
	case LOG_LPR:       return _T("lpr");
	case LOG_NEWS:      return _T("news");
	case LOG_UUCP:      return _T("uucp");
	case LOG_CRON:      return _T("cron");
	case LOG_AUTHPRIV:  return _T("authpriv");
	case LOG_FTP:       return _T("ftp");
	case LOG_LOCAL0:    return _T("local0");
	case LOG_LOCAL1:    return _T("local1");
	case LOG_LOCAL2:    return _T("local2");
	case LOG_LOCAL3:    return _T("local3");
	case LOG_LOCAL4:    return _T("local4");
	case LOG_LOCAL5:    return _T("local5");
	case LOG_LOCAL6:    return _T("local6");
	case LOG_LOCAL7:    return _T("local7");
	default:            return String();
	}
}

SyslogAppender::SyslogFacility SyslogAppender::getFacility(
	const String &facilityName)
{
	String s = StringHelper::toUpperCase(StringHelper::trim(facilityName));

	if (s == _T("KERN"))
	{
		return LOG_KERN;
	}
	else if (s == _T("USER"))
	{
		return LOG_USER;
	}
	else if (s == _T("MAIL"))
	{
		return LOG_MAIL;
	}
	else if (s == _T("DAEMON"))
	{
		return LOG_DAEMON;
	}
	else if (s == _T("AUTH"))
	{
		return LOG_AUTH;
	}
	else if (s == _T("SYSLOG"))
	{
		return LOG_SYSLOG;
	}
	else if (s == _T("LPR"))
	{
		return LOG_LPR;
	}
	else if (s == _T("NEWS"))
	{
		return LOG_NEWS;
	}
	else if (s == _T("UUCP"))
	{
		return LOG_UUCP;
	}
	else if (s == _T("CRON"))
	{
		return LOG_CRON;
	}
	else if (s == _T("AUTHPRIV"))
	{
		return LOG_AUTHPRIV;
	}
	else if (s == _T("FTP"))
	{
		return LOG_FTP;
	}
	else if (s == _T("LOCAL0"))
	{
		return LOG_LOCAL0;
	}
	else if (s == _T("LOCAL1"))
	{
		return LOG_LOCAL1;
	}
	else if (s == _T("LOCAL2"))
	{
		return LOG_LOCAL2;
	}
	else if (s == _T("LOCAL3"))
	{
		return LOG_LOCAL3;
	}
	else if (s == _T("LOCAL4"))
	{
		return LOG_LOCAL4;
	}
	else if (s == _T("LOCAL5"))
	{
		return LOG_LOCAL5;
	}
	else if (s == _T("LOCAL6"))
	{
		return LOG_LOCAL6;
	}
	else if (s == _T("LOCAL7"))
	{
		return LOG_LOCAL7;
	}
	else
	{
		return LOG_UNDEF;
	}
}

void SyslogAppender::append(const spi::LoggingEventPtr& event)
{
	if	(!isAsSevereAsThreshold(event->getLevel()))
		return;

	// We must not attempt to append if sqw is null.
	if(sw == 0)
	{
		errorHandler->error(_T("No syslog host is set for SyslogAppedender named \"")+
			this->name+_T("\"."));
		return;
	}

	StringBuffer sbuf;

	sbuf << _T("<") << (syslogFacility | event->getLevel()->getSyslogEquivalent()) << _T(">");
	if (facilityPrinting)
	{
		sbuf << facilityStr;
	}
	layout->format(sbuf, event);
	//LogLog::debug(sbuf.str());
	sw->write(sbuf.str());
}

void SyslogAppender::activateOptions()
{
}

void SyslogAppender::setSyslogHost(const String& syslogHost)
{
	this->sw = new SyslogWriter(syslogHost);
	this->syslogHost = syslogHost;
}


void SyslogAppender::setFacility(const String& facilityName)
{
	if (facilityName.empty())
	{
		return;
	}

	syslogFacility = getFacility(facilityName);
	if (syslogFacility == LOG_UNDEF)
	{
		LogLog::error(_T("[")+facilityName +
				_T("] is an unknown syslog facility. Defaulting to [USER]."));
		syslogFacility = LOG_USER;
	}

	this->initSyslogFacilityStr();
}

