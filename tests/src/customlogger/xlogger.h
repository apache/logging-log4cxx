/*
 * Copyright 2003,2004 The Apache Software Foundation.
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

#include <log4cxx/logger.h>
#include "../xml/xlevel.h"
#include <log4cxx/spi/loggerfactory.h>


namespace log4cxx
{
        namespace spi {
          namespace location {
            class LocationInfo;
          }
        }
        // Any sub-class of Logger must also have its own implementation of
        // CategoryFactory.
        class XFactory :
                public virtual spi::LoggerFactory,
                public virtual helpers::ObjectImpl
        {
        public:
                DECLARE_ABSTRACT_LOG4CXX_OBJECT(XFactory)
                BEGIN_LOG4CXX_CAST_MAP()
                        LOG4CXX_CAST_ENTRY(XFactory)
                        LOG4CXX_CAST_ENTRY(spi::LoggerFactory)
                END_LOG4CXX_CAST_MAP()

                XFactory();
                virtual LoggerPtr makeNewLoggerInstance(const LogString& name) const;
        };

        typedef helpers::ObjectPtrT<XFactory> XFactoryPtr;

        /**
        A simple example showing Logger sub-classing. It shows the
        minimum steps necessary to implement one's {@link LoggerFactory}.
        Note that sub-classes follow the hierarchy even if its loggers
        belong to different classes.
        */
        class XLogger : public Logger
        {
        // It's enough to instantiate a factory once and for all.
        static XFactoryPtr factory;
        LogString suffix;

        public:
                DECLARE_ABSTRACT_LOG4CXX_OBJECT(XLogger)
                BEGIN_LOG4CXX_CAST_MAP()
                        LOG4CXX_CAST_ENTRY(XLogger)
                        LOG4CXX_CAST_ENTRY_CHAIN(Logger)
                END_LOG4CXX_CAST_MAP()

                /**
                        Just calls the parent constuctor.
                */
                XLogger(const LogString& name) : Logger(name) {}

                /**
                        Nothing to activate.
                */
                void activateOptions() {}


                /**
                        We introduce a new printing method in order to support {@link
                        XLevel#LETHAL}.  */
                void lethal(const LogString& message, const log4cxx::spi::location::LocationInfo& location);

                /**
                        We introduce a new printing method in order to support {@link
                        XLevel#LETHAL}.  */
                void lethal(const LogString& message);

                static LoggerPtr getLogger(const LogString& name);

                static LoggerPtr getLogger(const helpers::Class& clazz);

                LogString getSuffix() const
                        { return suffix; }

                void setSuffix(const LogString& suffix)
                        { this->suffix = suffix; }

                /**
                        We introduce a new printing method that takes the TRACE level.
                */
                void trace(const LogString& message, const log4cxx::spi::location::LocationInfo& location);

                /**
                        We introduce a new printing method that takes the TRACE level.
                */
                void trace(const LogString& message);
        };

        typedef helpers::ObjectPtrT<XLogger> XLoggerPtr;
}

#define LOG4CXX_TRACE(logger, message) { \
        if (logger->isEnabledFor(log4cxx::XLevel::TRACE)) {\
          logger->forcedLog(log4cxx::XLevel::TRACE, message, LOG4CXX_LOCATION)
