/*
 * Copyright 2004 The Apache Software Foundation.
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

#ifndef _LOG4CXX_STREAM_H
#define _LOG4CXX_STREAM_H

#include <log4cxx/logger.h>
#include <sstream>
#include <log4cxx/spi/location/locationinfo.h>

namespace log4cxx
{
        /**
         * This template acts as a proxy for base_logstreamimpl
         * and defers the potentially expensive construction
         * of basic_stream until needed.
         */
        template <class Elem, class Tr = ::std::char_traits<Elem> >
           class basic_logstream : public ::std::ios_base {
             public:
             /**
              * Constructor.
              */
             basic_logstream(const ::log4cxx::LoggerPtr& loggr,
                          const ::log4cxx::LevelPtr& level) :
                          logger(loggr),
                          currentLevel(level),
                          impl(0),
                          enabled(loggr->isEnabledFor(level)) {
#if defined(_MSC_VER)
				_Init();
#endif
             }

            /**
             * Constructor.
             */
             basic_logstream(const char* logName,
               ::log4cxx::LevelPtr& level) :
               logger(::log4cxx::Logger::getLogger(logName)),
               currentLevel(level),
               impl(0),
               enabled(logger->isEnabledFor(level)) {
#if defined(_MSC_VER)
				_Init();
#endif
              }

              ~basic_logstream() {
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
                 return logger.isEnabledFor(level);
              }


              void setLocation(const ::log4cxx::spi::location::LocationInfo& location) {
                 if (LOG4CXX_UNLIKELY(enabled)) {
                    currentLocation = location;
                 }
              }



             inline void flush(const ::log4cxx::spi::location::LocationInfo& location) {
                 if (LOG4CXX_UNLIKELY(enabled && 0 != impl)) {
                    logger->log(currentLevel,
                       impl->str(),
                       location.getFileName(),
                       location.getLineNumber());
					const std::basic_string<Elem, Tr> emptyStr;
                    impl->str(emptyStr);
                }
             }

             inline void flush() {
                flush(currentLocation);
             }


             ::std::basic_ostream<Elem, Tr>& getStream() {
                if (0 == impl) {
                  impl = new ::std::basic_ostringstream<Elem, Tr>();
                }
                impl->precision(precision());
                impl->width(width());
                impl->flags(flags());
                return *impl;
             }

             private:
             LevelPtr currentLevel;
             LoggerPtr logger;
             ::log4cxx::spi::location::LocationInfo currentLocation;
             bool enabled;
             ::std::basic_ostringstream<Elem, Tr>* impl;

        };

	typedef basic_logstream<char> logstream;
	typedef basic_logstream<wchar_t> wlogstream;
}  // namespace log4cxx



//
//   Insertion operators for LocationInfo, LocationFlush, Level and
//      manipulators (std::fixed and similar)
//
//   Visual C++ 6 and earlier do not implement template partial ordering
//     (see http://support.microsoft.com/default.aspx?scid=kb;en-us;240869)
//     resulting in error C2667 unless the non-template definitions for
//     operator<< (LOG4CXX_DEFINE_LOCATION_INSERTION and similar) are provided.
//

#define LOG4CXX_DEFINE_LOCATION_INSERTION(streamtype)        \
streamtype& operator<<(streamtype& lhs,                      \
const ::log4cxx::spi::location::LocationInfo& rhs) {         \
   lhs.setLocation(rhs);                                     \
   return lhs;                                               \
}


#define LOG4CXX_DEFINE_FLUSH_INSERTION(streamtype)            \
streamtype& operator<<(streamtype& lhs,                       \
const ::log4cxx::spi::location::LocationFlush& rhs) {         \
   lhs.flush(rhs);                                            \
   return lhs;                                                \
}



#define LOG4CXX_DEFINE_LEVEL_INSERTION(streamtype)    \
streamtype& operator<<(streamtype& lhs,               \
const ::log4cxx::LevelPtr& rhs) {                     \
   lhs.setLevel(rhs);                                 \
   return lhs;                                        \
}


#define LOG4CXX_DEFINE_MANIPULATOR_INSERTION(streamtype)        \
streamtype& operator<<(                                 \
   streamtype& lhs,                                     \
::std::ios_base& (*manip)(::std::ios_base&)) {          \
     (*manip)(lhs);                                     \
   return lhs;                                          \
}

#if _MSC_VER_ < 1300
LOG4CXX_DEFINE_LOCATION_INSERTION(::log4cxx::logstream)
LOG4CXX_DEFINE_LOCATION_INSERTION(::log4cxx::wlogstream)


LOG4CXX_DEFINE_FLUSH_INSERTION(::log4cxx::logstream)
//LOG4CXX_DEFINE_FLUSH_INSERTION(::log4cxx::wlogstream)

LOG4CXX_DEFINE_LEVEL_INSERTION(::log4cxx::logstream)
LOG4CXX_DEFINE_LEVEL_INSERTION(::log4cxx::wlogstream)

LOG4CXX_DEFINE_MANIPULATOR_INSERTION(::log4cxx::logstream)
LOG4CXX_DEFINE_MANIPULATOR_INSERTION(::log4cxx::wlogstream)
#else

template<class Elem, class Tr>
::log4cxx::basic_logstream<Elem, Tr>& operator<<(
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,
   const ::log4cxx::spi::location::LocationInfo& rhs) {
   lhs.setLocation(rhs);
   return lhs;
}


template<class Elem, class Tr>
::log4cxx::basic_logstream<Elem, Tr>& operator<<(
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,
   const ::log4cxx::spi::location::LocationFlush& rhs) {
   lhs.flush(rhs);
   return lhs;
}

template<class Elem, class Tr>
::log4cxx::basic_logstream<Elem, Tr>& operator<<(
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,
   const ::log4cxx::LevelPtr& rhs) {
   lhs.setLevel(rhs);
   return lhs;
}


template<class Elem, class Tr>
::log4cxx::basic_logstream<Elem, Tr>& operator<<(
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,
   ::std::ios_base& (*manip)(::std::ios_base&)) {
     (*manip)(lhs);
   return lhs;
}
#endif




//
//   template for all other insertion operators
//
template<class Elem, class Tr, class ArbitraryType>
::log4cxx::basic_logstream<Elem, Tr>& operator<<(
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,
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
