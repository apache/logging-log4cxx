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

#ifndef _LOG4CXX_SPI_LOCATION_LOCATIONINFO_H
#define _LOG4CXX_SPI_LOCATION_LOCATIONINFO_H

#include <log4cxx/portability.h>
#include <string>

namespace log4cxx
{
  namespace spi
  {
    namespace location
    {
      /**
       * This class represents the location of a logging statement.
       *
       * @remarks This class currently only used by the experimental (and optional) log4cxx::stream class.
       */
      class LOG4CXX_EXPORT LocationInfo
      {
      public:



      /**
        *   When location information is not available the constant
        * <code>NA</code> is returned. Current value of this string constant is <b>?</b>.
        */
        static const char * const NA;

        static const LocationInfo& getLocationUnavailable();



       /**
        *   Constructor.
        *   @remarks Used by LOG4CXX_LOCATION to generate
        *       location info for current code site
        */
        LocationInfo( const char * const fileName,
                      const char * const className,
                      const char * const methodName,
                      int lineNumber);

       /**
        *   Default constructor.
        */
        LocationInfo();

       /**
        *   Copy constructor.
        *   @param src source location
        */
        LocationInfo( const LocationInfo & src );

       /**
        *  Assignment operator.
        * @param src source location
        */
        LocationInfo & operator = ( const LocationInfo & src );

        /**
         *   Resets location info to default state.
         */
        void clear();


        /** Return the class name of the call site. */
        const std::string getClassName() const;

        /**
         *   Return the file name of the caller.
         *   @returns file name, may be null.
         */
        const char * getFileName() const;

        /**
          *   Returns the line number of the caller.
          * @returns line number, -1 if not available.
          */
        int getLineNumber() const;

        /** Returns the method name of the caller. */
        const char * getMethodName() const;

        private:
        /** Caller's line number. */
        int lineNumber;

        /** Caller's file name. */
        const char * fileName;

        /** Caller's fully qualified class name. */
        const char * className;

        /** Caller's method name. */
        const char * methodName;


      };


      class LOG4CXX_EXPORT LocationFlush : public LocationInfo {
      	public:
       /**
        *   Constructor.
        *   @remarks Used by LOG4CXX_LOCATION_FLUSH to generate
        *       location info for current code site and
        *       flush a logging stream
        */
        LocationFlush( const char * const fileName,
                      const char * const className,
                      const char * const methodName,
                      int lineNumber )
             : LocationInfo( fileName, className, methodName, lineNumber ) {
        }
      };
    }
  }
}

  #if !defined(LOG4CXX_LOCATION)
    #if defined(__PRETTY_FUNCTION__)
      #define LOG4CXX_LOCATION ::log4cxx::spi::location::LocationInfo(__FILE__, \
           __PRETTY_FUNCTION__,                                              \
           __func__,                                                         \
           __LINE__)
      #define LOG4CXX_LOCATION_FLUSH ::log4cxx::spi::location::LocationFlush(__FILE__, \
           __PRETTY_FUNCTION__,                                              \
           __func__,                                                         \
           __LINE__)
    #else
      #if defined(__FUNCSIG__)
        #define LOG4CXX_LOCATION ::log4cxx::spi::location::LocationInfo(__FILE__, \
             __FUNCSIG__,                                                      \
             __FUNCTION__,                                                     \
             __LINE__)
        #define LOG4CXX_LOCATION_FLUSH ::log4cxx::spi::location::LocationFlush(__FILE__, \
             __FUNCSIG__,                                                      \
             __FUNCTION__,                                                     \
             __LINE__)
      #else
        #if defined(__func__)
          #define LOG4CXX_LOCATION ::log4cxx::spi::location::LocationInfo(__FILE__, \
             ::log4cxx::spi::location::LocationInfo::NA,                       \
             __func__,                                                         \
             __LINE__)
          #define LOG4CXX_LOCATION_FLUSH ::log4cxx::spi::location::LocationFlush(__FILE__, \
             ::log4cxx::spi::location::LocationInfo::NA,                       \
             __func__,                                                         \
             __LINE__)
        #else
          #define LOG4CXX_LOCATION ::log4cxx::spi::location::LocationInfo(__FILE__, \
             ::log4cxx::spi::location::LocationInfo::NA,                       \
             ::log4cxx::spi::location::LocationInfo::NA,                                                         \
             __LINE__)
          #define LOG4CXX_LOCATION_FLUSH ::log4cxx::spi::location::LocationFlush(__FILE__, \
             ::log4cxx::spi::location::LocationInfo::NA,                       \
             ::log4cxx::spi::location::LocationInfo::NA,                                                         \
             __LINE__)
          #endif
        #endif
    #endif
  #endif

#endif //_LOG4CXX_SPI_LOCATION_LOCATIONINFO_H
