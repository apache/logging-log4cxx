/*
 * Copyright 2004-2005 The Apache Software Foundation.
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
      /**
       * This class represents the location of a logging statement.
       *
       */
      class LOG4CXX_EXPORT LocationInfo
      {
      public:



      /**
        *   When location information is not available the constant
        * <code>NA</code> is returned. Current value of this string constant is <b>?</b>.
        */
        static const char * const NA;
        static const char * const NA_METHOD;

        static const LocationInfo& getLocationUnavailable();



       /**
        *   Constructor.
        *   @remarks Used by LOG4CXX_LOCATION to generate
        *       location info for current code site
        */
        LocationInfo( const char * const fileName,
                      const char * const functionName,
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
        const std::string getMethodName() const;

        private:
        /** Caller's line number. */
        int lineNumber;

        /** Caller's file name. */
        const char * fileName;

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
                      const char * const methodName,
                      int lineNumber )
             : LocationInfo( fileName, methodName, lineNumber ) {
        }

      };
  }
}

  #if !defined(LOG4CXX_LOCATION)
#if defined(_MSC_VER)
#if _MSC_VER >= 1300
      #define __LOG4CXX_FUNC__ __FUNCSIG__
#endif
#else
#if defined(__GCC)
      #define __LOG4CXX_FUNC__ __PRETTY_FUNCTION__
#endif
#endif
#if !defined(__LOG4CXX_FUNC__)
#define __LOG4CXX_FUNC__ ""
#endif
      #define LOG4CXX_LOCATION ::log4cxx::spi::LocationInfo(__FILE__, \
           __LOG4CXX_FUNC__,                                                         \
           __LINE__)
      #define LOG4CXX_LOCATION_FLUSH ::log4cxx::spi::LocationFlush(__FILE__, \
           __LOG4CXX_FUNC__,                                                         \
           __LINE__)
  #endif

#endif //_LOG4CXX_SPI_LOCATION_LOCATIONINFO_H
