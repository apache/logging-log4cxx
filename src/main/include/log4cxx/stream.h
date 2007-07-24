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

#ifndef _LOG4CXX_STREAM_H
#define _LOG4CXX_STREAM_H

#include <log4cxx/logger.h>
#include <sstream>
#include <log4cxx/spi/location/locationinfo.h>

namespace log4cxx
{
#if LOG4CXX_HAS_WCHAR_T
typedef wchar_t logstream_char;
#else
typedef char logstream_char;
#endif
        /**
         * This template acts as a proxy for base_logstreamimpl
         * and defers the potentially expensive construction
         * of basic_stream until needed.
         */
           class logstream : public ::std::basic_ios<logstream_char> {
             public:
             /**
              * Constructor.
              */
             logstream(const ::log4cxx::LoggerPtr& loggr,
                          const ::log4cxx::LevelPtr& level) :
                          logger(loggr),
                          currentLevel(level),
                          impl(0),
                          enabled(loggr->isEnabledFor(level)),
                          currentLocation() {
                          init(0);
             }

            /**
             * Constructor.
             */
             logstream(const char* logName,
               ::log4cxx::LevelPtr& level) :
               logger(::log4cxx::Logger::getLogger(logName)),
               currentLevel(level),
               impl(0),
               enabled(logger->isEnabledFor(level)),
               currentLocation() {
                   init(0);
              }

#if LOG4CXX_HAS_WCHAR_T
              /**
               * Constructor.
               */
               logstream(const wchar_t* logName,
                 ::log4cxx::LevelPtr& level) :
                 logger(::log4cxx::Logger::getLogger(logName)),
                 currentLevel(level),
                 impl(0),
                 enabled(logger->isEnabledFor(level)),
                 currentLocation() {
                     init(0);
                }
#endif

              ~logstream() {
                  delete impl;
              }



             /**
              * Set the level.
              * @param level level
              */
              void setLevel(const ::log4cxx::LevelPtr& level) {
                  currentLevel = level;
                  enabled = logger->isEnabledFor(currentLevel);
              }

              inline bool isEnabled() const {
                 return enabled;
              }

              bool isEnabledFor(const ::log4cxx::LevelPtr& level) const {
                 return logger->isEnabledFor(level);
              }


              void setLocation(const ::log4cxx::spi::LocationInfo& location) {
                 if (LOG4CXX_UNLIKELY(enabled)) {
                    currentLocation = location;
                 }
              }



             inline void flush(const ::log4cxx::spi::LocationInfo& location) {
                 if (LOG4CXX_UNLIKELY(enabled && 0 != impl)) {
                    logger->log(currentLevel,
                       impl->str(),
                       location);
                    const std::basic_string<logstream_char> emptyStr;
                    impl->str(emptyStr);
                }
             }

             inline void flush() {
                flush(currentLocation);
             }


             ::std::basic_ostream<logstream_char>& getStream() {
                if (0 == impl) {
                  impl = new ::std::basic_ostringstream<logstream_char>();
                }
                impl->flags(flags());
                impl->precision(precision());
                impl->width(width());
                return *impl;
             }

             private:
             logstream(const logstream&);
             logstream& operator=(const logstream&);
             LoggerPtr logger;
             LevelPtr currentLevel;
             ::std::basic_ostringstream<logstream_char>* impl;
             bool enabled;
             ::log4cxx::spi::LocationInfo currentLocation;

        };

}  // namespace log4cxx


LOG4CXX_EXPORT ::log4cxx::logstream& operator<<(
  ::log4cxx::logstream& lhs,
  const char* rhs);

LOG4CXX_EXPORT ::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   const ::log4cxx::LogString& rhs);


LOG4CXX_EXPORT ::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   const ::log4cxx::spi::LocationInfo& rhs);


LOG4CXX_EXPORT ::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   const ::log4cxx::spi::LocationFlush& rhs);


LOG4CXX_EXPORT ::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   const ::log4cxx::LevelPtr& rhs);


LOG4CXX_EXPORT ::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   ::std::ios_base& (*manip)(::std::ios_base&));


//
//   template for all other insertion operators
//
template<class ArbitraryType>
::log4cxx::logstream& operator<<(
   ::log4cxx::logstream& lhs,
   const ArbitraryType& rhs) {
   if (LOG4CXX_UNLIKELY(lhs.isEnabled())) {
       lhs.getStream() << rhs;
   }
   return lhs;
}


#if !defined(LOG4CXX_ENDMSG)
#define LOG4CXX_ENDMSG LOG4CXX_LOCATION_FLUSH
#endif


#endif //_LOG4CXX_STREAM_H
