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

#ifndef LOG4CXX_DB_DB_APPENDER_H
#define LOG4CXX_DB_DB_APPENDER_H

#include <log4cxx/log4cxx.h>

#include <log4cxx/helpers/exception.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/spi/loggingevent.h>
#include <list>
#include <memory>

namespace log4cxx
{
namespace db
{

/**
 *
<appender name="SqlDBAppender" class="DBAppender">
 <param name="drivername" value="odbc"/>
 <param name="sql" value="INSERT INTO logs (log, time, level, file, line, message) VALUES (%s, %s, %s, %s, %s, %s)" />
 <param name="DatabaseName" value="foo"/>
 <param name="DriverParams" value="DATASOURCE=MariaDB-server"/>
 <param name="ColumnMapping" value="logger"/>
 <param name="ColumnMapping" value="time"/>
 <param name="ColumnMapping" value="level"/>
 <param name="ColumnMapping" value="shortfilename"/>
 <param name="ColumnMapping" value="line"/>
 <param name="ColumnMapping" value="message"/>
</appender>

CREATE TABLE logs (thread VARCHAR(200),
 log VARCHAR(200),
 time VARCHAR(200),
 level VARCHAR(10),
 file VARCHAR(200),
 line VARCHAR(10),
 message VARCHAR(1000)
);
 */
class LOG4CXX_EXPORT DBAppender : public AppenderSkeleton
{
        public:
                DECLARE_LOG4CXX_OBJECT(DBAppender)
                BEGIN_LOG4CXX_CAST_MAP()
                LOG4CXX_CAST_ENTRY(DBAppender)
                LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
                END_LOG4CXX_CAST_MAP()

                DBAppender();
                virtual ~DBAppender();

                /**
                Set options
                */
                void setOption(const LogString& option, const LogString& value) override;

                /**
                Activate the specified options.
                */
                void activateOptions(helpers::Pool& p) override;

                /**
                * Adds the event to the buffer.  When full the buffer is flushed.
                */
                void append(const spi::LoggingEventPtr& event, helpers::Pool&) override;

                void close() override;

                /**
                * DBAppender does not require a layout.
                * */
                bool requiresLayout() const override
                {
                        return false;
                }

                /**
                * Set pre-formated statement eg: insert into LogTable (msg) values ("%m")
                */
                void setSql(const LogString& s);

                /**
                * Returns pre-formated statement eg: insert into LogTable (msg) values ("%m")
                */
                const LogString& getSql() const;


//                void setUser(const LogString& user);

//                void setURL(const LogString& url);

//                void setPassword(const LogString& password);

//                void setBufferSize(size_t newBufferSize);

//                const LogString& getUser() const;

//                const LogString& getURL() const;

//                const LogString& getPassword() const;

//                size_t getBufferSize() const;
        private:
                DBAppender(const DBAppender&);
                DBAppender& operator=(const DBAppender&);
#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR_T || defined(WIN32) || defined(_WIN32)
                static void encode(wchar_t** dest, const LogString& src,
                        log4cxx::helpers::Pool& p);
#endif
                static void encode(unsigned short** dest, const LogString& src,
                        log4cxx::helpers::Pool& p);

        protected:
                struct DBAppenderPriv;
}; // class DBAppender

LOG4CXX_PTR_DEF(DBAppender);

} // namespace db
} // namespace log4cxx

#endif // LOG4CXX_DB_DB_APPENDER_H
