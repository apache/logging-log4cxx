/*
 * Copyright 1999,2005 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if !defined(_LOG4CXX_ROLLING_ROLLING_FILE_APPENDER_H)
#define _LOG4CXX_ROLLING_ROLLING_FILE_APPENDER_H

#include <log4cxx/portability.h>
#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/rolling/triggeringpolicy.h>
#include <log4cxx/rolling/rollingpolicy.h>

namespace log4cxx {
    namespace rolling {

        /**
         * <code>RollingFileAppender</code> extends {@link FileAppender} to backup the log files
         * depending on {@link RollingPolicy} and {@link TriggeringPolicy}.
         * <p>
         * To be of any use, a <code>RollingFileAppender</code> instance must have both 
         * a <code>RollingPolicy</code> and a <code>TriggeringPolicy</code> set up. 
         * However, if its <code>RollingPolicy</code> also implements the
         * <code>TriggeringPolicy</code> interface, then only the former needs to be
         * set up. For example, {@link TimeBasedRollingPolicy} acts both as a
         * <code>RollingPolicy</code> and a <code>TriggeringPolicy</code>.
         * 
         * <p><code>RollingFileAppender</code> can be configured programattically or
         * using {@link org.apache.log4j.joran.JoranConfigurator}. Here is a sample
         * configration file:

        <pre>&lt;?xml version="1.0" encoding="UTF-8" ?>
        &lt;!DOCTYPE log4j:configuration>

        &lt;log4j:configuration debug="true">

          &lt;appender name="ROLL" class="org.apache.log4j.rolling.RollingFileAppender">
            <b>&lt;rollingPolicy class="org.apache.log4j.rolling.TimeBasedRollingPolicy">
              &lt;param name="FileNamePattern" value="/wombat/foo.%d{yyyy-MM}.gz"/>
            &lt;/rollingPolicy></b>

            &lt;layout class="org.apache.log4j.PatternLayout">
              &lt;param name="ConversionPattern" value="%c{1} - %m%n"/>
            &lt;/layout>     
          &lt;/appender>

          &lt;root">
            &lt;appender-ref ref="ROLL"/>
          &lt;/root>
 
        &lt;/log4j:configuration>
        </pre>

         *<p>This configuration file specifies a monthly rollover schedule including
         * automatic compression of the archived files. See 
         * {@link TimeBasedRollingPolicy} for more details.
         * 
         * @author Heinz Richter
         * @author Ceki G&uuml;lc&uuml;
         * @since  1.3
         * */
        class LOG4CXX_EXPORT RollingFileAppender : public FileAppender {
        private:
          File activeFile;
          TriggeringPolicyPtr triggeringPolicy;
          RollingPolicyPtr rollingPolicy;

        public:
          /**
           * The default constructor simply calls its {@link
           * FileAppender#FileAppender parents constructor}.
           * */
          RollingFileAppender();

          void activateOptions(log4cxx::helpers::Pool&);


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

           */
          void rollover();

        protected:

          /**
             This method differentiates RollingFileAppender from its super
             class.
          */
          void subAppend(log4cxx::spi::LoggingEvent& event);

        public:

          const RollingPolicyPtr& getRollingPolicy() const;

          const TriggeringPolicyPtr& getTriggeringPolicy() const;

          /**
           * Sets the rolling policy. In case the 'policy' argument also implements
           * {@link TriggeringPolicy}, then the triggering policy for this appender
           * is automatically set to be the policy argument.
           * @param policy
           */
          void setRollingPolicy(const RollingPolicyPtr& policy);

          void setTriggeringPolicy(const TriggeringPolicyPtr& policy);
        };

        typedef log4cxx::helpers::ObjectPtrT<RollingFileAppender> RollingFileAppenderPtr;

    }
}

#endif

