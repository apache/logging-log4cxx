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
	 * Implements an STL streambuf for use by logging streams.
	 */
	template <class Elem, class Tr = ::std::char_traits<Elem> >
	   class basic_logstreambuf : public ::std::basic_stringbuf<Elem, Tr> {
	   public:
	   /**
	    * Constructor.
	    *
	    */
	   basic_logstreambuf(const ::log4cxx::LoggerPtr& logger,
	                   const ::log4cxx::LevelPtr& level) :
	                   ::std::basic_stringbuf<Elem, Tr>(::std::ios_base::out),
	                   logger(logger),
	                   level(level)  {
	        enabled = logger->isEnabledFor(level);
	   }

       /**
        * Gets whether logger is currently enabled for the specified level.
        * @returns true if enabled
        */
	   inline bool isEnabled() const {
	   	  return enabled;
	   }

	   /**
	    * Sets the call site location.
	    * @param location call site location
	    */
	   void setLocation(const ::log4cxx::spi::location::LocationInfo& location) {
	   	   this->location = location;
	   }

	   /**
	    * Sets the level.
	    * @param level level
	    */
	   void setLevel(const ::log4cxx::LevelPtr& level) {
	   	  bool newState = logger->isEnabledFor(level);
	   	  //
	   	  //    if not previously enabled but soon to be enabled then
	   	  //       reset the buffer to clear any previously inserted content
	   	  if (newState && !enabled) {
	   	     //
	   	     //   reset the stream buffer
	   	     seekoff(0, ::std::ios_base::beg, ::std::ios_base::out);
	   	  }
	   	  this->level = level;
	   	  enabled = newState;
	   }

       protected:
       /**
        * Synchronizes the stream and logger.
        *
        */
	   int sync() {
	   	  //
	   	  //  if previously enabled
	   	  if (enabled) {
	   	  	 //  check (and cache) whether it is still enabled
	   	     enabled = logger->isEnabledFor(level);
	   	     //  log message if still enabled
	   	     if (enabled) {
	   	          logger->forcedLog(level,
	   	              str(),
	   	              location.getFileName(),
	   	              location.getLineNumber());
	   	     }
	   	  }
	   	  //  clear call site information
          location.clear();
	   	  //
	   	  //   reset the stream buffer
	   	  seekoff(0, ::std::ios_base::beg, ::std::ios_base::out);
	   	  return 0;
	   }

       bool isEnabledFor(const ::log4cxx::LevelPtr& level) const {
       	   return logger.isEnabledFor(level);
       }

	   private:
	   /**
	    * logger.
	    */
	   ::log4cxx::LoggerPtr logger;
	   /**
	    * level.
	    */
	   ::log4cxx::LevelPtr level;
	   /**
	    * location.
	    */
	   ::log4cxx::spi::location::LocationInfo location;

       /**
        * State of logger at last sync or level changes.
        */
       bool enabled;

	};

	/**
	 * This template provides an stream interface layer to
	 * log4cxx.
	 */
	template <class Elem, class Tr = ::std::char_traits<Elem> >
	   class basic_logstream : public ::std::basic_ostream<Elem, Tr> {

	   public:
	   /**
	    * Constructor.
	    */
	   basic_logstream(const ::log4cxx::LoggerPtr& logger,
	                const ::log4cxx::LevelPtr& level) :
	                ::std::basic_ostream<Elem, Tr>(&buffer),
	                buffer(logger, level) {
	   }

          /**
           * Constructor.
           */
           basic_logstream(const char* logName,
             ::log4cxx::LevelPtr& level) :
             ::std::basic_ostream<Elem, Tr>(&buffer),
             buffer(::log4cxx::Logger::getLogger(logName), level) {
            }


          /**
           * Sets the call site location.
           * @param location call site location
           */
	   void setLocation(const ::log4cxx::spi::location::LocationInfo& location) {
	   	   buffer.setLocation(location);
	   }


	   /**
	    * Set the level.
	    * @param level level
	    */
	   void setLevel(const ::log4cxx::LevelPtr& level) {
	   	  buffer.setLevel(level);
	   }

       inline bool isEnabled() const {
           return buffer.isEnabled();
       }
       
       bool isEnabledFor(const ::log4cxx::LevelPtr& level) const {
       	   return buffer.isEnabledFor(level);
       }


	   private:
	   basic_logstreambuf<Elem, Tr> buffer;
	};

	typedef basic_logstream<char> logstream;
	typedef basic_logstream<wchar_t> wlogstream;
}  // namespace log4cxx

/**
* Insertion operator for LocationInfo.
*
*/
template<class Elem, class Tr>
::log4cxx::basic_logstream<Elem, Tr>& operator<<(
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,
   const ::log4cxx::spi::location::LocationInfo& rhs) {
   if (LOG4CXX_UNLIKELY(lhs.isEnabled())) {
      lhs.setLocation(rhs);
   }
   return lhs;
}

/**
* Insertion operator for LocationFlush.
*
*/
template<class Elem, class Tr>
::log4cxx::basic_logstream<Elem, Tr>& operator<<(
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,
   const ::log4cxx::spi::location::LocationFlush& rhs) {
   if (LOG4CXX_UNLIKELY(lhs.isEnabled())) {
   	  lhs.setLocation(rhs);
   	  lhs.flush();
   }
   return lhs;
}


/**
* Insertion operator for LocationInfo.
*
*/
template<class Elem, class Tr>
::log4cxx::basic_logstream<Elem, Tr>& operator<<(
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,
   const ::log4cxx::LevelPtr& rhs) {
   lhs.setLevel(rhs);
   return lhs;
}


#define LOG4CXX_STREAM_DEFINE_INSERTION(InsType)           \
template<class Elem, class Tr>                             \
::log4cxx::basic_logstream<Elem, Tr>& operator<<(          \
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,              \
   InsType rhs) {                                          \
   if (LOG4CXX_UNLIKELY(lhs.isEnabled())) {                \
      ((::std::basic_ostream<Elem, Tr>&) lhs) << rhs;      \
   }                                                       \
   return lhs;                                             \
}



/*
* Insertion operators for common types.
* Can't use template or would get ambiguities.
* If attempting to insert a type without a matching
* logstream specific insertion operator, the type
* will be formatted, but may get discarded.
*
*/
LOG4CXX_STREAM_DEFINE_INSERTION(bool)
LOG4CXX_STREAM_DEFINE_INSERTION(signed char)
LOG4CXX_STREAM_DEFINE_INSERTION(unsigned char)
LOG4CXX_STREAM_DEFINE_INSERTION(signed short)
LOG4CXX_STREAM_DEFINE_INSERTION(unsigned short)
LOG4CXX_STREAM_DEFINE_INSERTION(signed int)
LOG4CXX_STREAM_DEFINE_INSERTION(unsigned int)
LOG4CXX_STREAM_DEFINE_INSERTION(signed long)
LOG4CXX_STREAM_DEFINE_INSERTION(unsigned long)
LOG4CXX_STREAM_DEFINE_INSERTION(float)
LOG4CXX_STREAM_DEFINE_INSERTION(double)
LOG4CXX_STREAM_DEFINE_INSERTION(const Elem*)

template<class Elem, class Tr>
::log4cxx::basic_logstream<Elem, Tr>& operator<<(
   ::log4cxx::basic_logstream<Elem, Tr>& lhs,
   const ::std::basic_string<Elem, Tr>& rhs) {
   if (LOG4CXX_UNLIKELY(lhs.isEnabled())) {
      ((::std::basic_ostream<Elem, Tr>&) lhs) << rhs;
   }
   return lhs;
}


#if !defined(LOG4CXX_ENDMSG)
#define LOG4CXX_ENDMSG LOG4CXX_LOCATION_FLUSH
#endif


#endif //_LOG4CXX_STREAM_H
