/***************************************************************************
                          syslogappender.h  -  class SyslogAppender
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

#ifndef _LOG4CXX_NET_SYSLOG_APPENDER_H
#define _LOG4CXX_NET_SYSLOG_APPENDER_H
 
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/syslogwriter.h>

namespace log4cxx
{
	namespace net
	{
		class SyslogAppender;
		typedef helpers::ObjectPtrT<SyslogAppender> SyslogAppenderPtr;

		/** Use SyslogAppender to send log messages to a remote syslog daemon.*/
		class LOG4CXX_EXPORT SyslogAppender : public AppenderSkeleton
		{
		public:
			DECLARE_LOG4CXX_OBJECT(SyslogAppender)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(SyslogAppender)
				LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
			END_LOG4CXX_CAST_MAP()

			typedef enum
			{
				/** Kernel messages */
				LOG_KERN     = 0,
				/** Random user-level messages */
				LOG_USER     = 1<<3,
				/** Mail system */
				LOG_MAIL     = 2<<3,
				/** System daemons */
				LOG_DAEMON   = 3<<3,
				/** security/authorization messages */
				LOG_AUTH     = 4<<3,
				/** messages generated internally by syslogd */
				LOG_SYSLOG   = 5<<3,

				/** line printer subsystem */
				LOG_LPR      = 6<<3,
				/** network news subsystem */
				LOG_NEWS     = 7<<3,
				/** UUCP subsystem */
				LOG_UUCP     = 8<<3,
				/** clock daemon */
				LOG_CRON     = 9<<3,
				/** security/authorization  messages (private) */
				LOG_AUTHPRIV = 10<<3,
				/** ftp daemon */
				LOG_FTP      = 11<<3,

				// other codes through 15 reserved for system use
				/** reserved for local use */
				LOG_LOCAL0 = 16<<3,
				/** reserved for local use */
				LOG_LOCAL1 = 17<<3,
				/** reserved for local use */
				LOG_LOCAL2 = 18<<3,
				/** reserved for local use */
				LOG_LOCAL3 = 19<<3,
				/** reserved for local use */
				LOG_LOCAL4 = 20<<3,
				/** reserved for local use */
				LOG_LOCAL5 = 21<<3,
				/** reserved for local use */
				LOG_LOCAL6 = 22<<3,
				/** reserved for local use*/
				LOG_LOCAL7 = 23<<3,

				LOG_UNDEF = -1
			} SyslogFacility;

			SyslogAppender();
			SyslogAppender(const LayoutPtr& layout, SyslogFacility syslogFacility);
			SyslogAppender(const LayoutPtr& layout,
				const String& syslogHost, SyslogFacility syslogFacility);
			~SyslogAppender();
			/** Release any resources held by this SyslogAppender.*/
			void close();

			/**
			Returns the specified syslog facility as a lower-case String,
			e.g. "kern", "user", etc.
			*/
			static String getFacilityString(SyslogFacility syslogFacility);

			/**
			Returns the integer value corresponding to the named syslog
			facility, or -1 if it couldn't be recognized.
			@param facilityName one of the strings KERN, USER, MAIL, DAEMON,
			AUTH, SYSLOG, LPR, NEWS, UUCP, CRON, AUTHPRIV, FTP, LOCAL0,
			LOCAL1, LOCAL2, LOCAL3, LOCAL4, LOCAL5, LOCAL6, LOCAL7.
			The matching is case-insensitive.
			*/
			static SyslogFacility getFacility(const String &facilityName);

			void append(const spi::LoggingEventPtr& event);

			/**
			This method returns immediately as options are activated when they
			are set.
			*/
			void activateOptions();

			/**
			The SyslogAppender requires a layout. Hence, this method returns
			<code>true</code>.
			*/
			virtual bool requiresLayout() const
				{ return true; }

			/**
			The <b>SyslogHost</b> option is the name of the the syslog host
			where log output should go.
			<b>WARNING</b> If the SyslogHost is not set, then this appender
			will fail.
			*/
			void setSyslogHost(const String& syslogHost);

			/**
			Returns the value of the <b>SyslogHost</b> option.
			*/
			inline const String& getSyslogHost() const
				{ return syslogHost; }

			/**
			Set the syslog facility. This is the <b>Facility</b> option.

			<p>The <code>facilityName</code> parameter must be one of the
			strings KERN, USER, MAIL, DAEMON, AUTH, SYSLOG, LPR, NEWS, UUCP,
			CRON, AUTHPRIV, FTP, LOCAL0, LOCAL1, LOCAL2, LOCAL3, LOCAL4,
			LOCAL5, LOCAL6, LOCAL7. Case is unimportant.
			*/
			void setFacility(const String& facilityName);

			/**
			Returns the value of the <b>Facility</b> option.
			*/
			inline String getFacility() const
				{ return getFacilityString(syslogFacility); }

			/**
			If the <b>FacilityPrinting</b> option is set to true, the printed
			message will include the facility name of the application. It is
			<em>false</em> by default.
			*/
			inline void setFacilityPrinting(bool facilityPrinting)
				{ this->facilityPrinting = facilityPrinting; }

			/**
			Returns the value of the <b>FacilityPrinting</b> option.
			*/
			inline bool getFacilityPrinting() const
				{ return facilityPrinting; }

		protected:
			void initSyslogFacilityStr();

			SyslogFacility syslogFacility; // Have LOG_USER as default
			String facilityStr;
			bool facilityPrinting;
			helpers::SyslogWriter * sw;
			String syslogHost;

		}; // class SyslogAppender
    } // namespace net
}; // namespace log4cxx

#endif // _LOG4CXX_NET_SYSLOG_APPENDER_H

