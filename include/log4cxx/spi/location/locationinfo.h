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
      class LocationInfo
      {
      public:



      /**
        *   When location information is not available the constant
        * <code>NA</code> is returned. Current value of this string constant is <b>?</b>.
        */
        static const char * const NA;


        /**
         * NA_LOCATION_INFO when  real location info is not available.
         */
        static LocationInfo NA_LOCATION_INFO;


       /**
        *   Constructor.
        *   @remarks Used by LOG4CXX_LOCATION to generate
        *       location info for current code site
        */
        LocationInfo( const char * const fileName,
                      const char * const className,
                      const char * const methodName,
                      int lineNumber )
             : fileName( fileName ),
               className( className ),
               methodName( methodName ),
               lineNumber( lineNumber )
             {
        }

       /**
        *   Default constructor.
        */
        LocationInfo()
           : fileName(LocationInfo::NA),
             className(LocationInfo::NA),
             methodName(LocationInfo::NA),
             lineNumber(-1) {
        }

       /**
        *   Copy constructor.
        *   @param src source location
        */
        LocationInfo( const LocationInfo & src )
             : fileName( src.fileName ),
               className( src.className ),
               methodName( src.methodName ),
               lineNumber( src.lineNumber )
             {
        }

       /**
        *  Assignment operator.
        * @param src source location
        */
        LocationInfo & operator = ( const LocationInfo & src )
        {
          fileName = src.fileName;
          className = src.className;
          methodName = src.methodName;
          lineNumber = src.lineNumber;
          return * this;
        }

        /**
         *   Resets location info to default state.
         */
        void clear() {
          fileName = NA;
          className = NA;
          methodName = NA;
          lineNumber = -1;
        }


        /** Return the class name of the call site. */
        const std::string getClassName() const;

        /**
         *   Return the file name of the caller.
         *   @returns file name, may be null.
         */
        const char * getFileName() const
        {
          return fileName;
        }

        /**
          *   Returns the line number of the caller.
          * @returns line number, -1 if not available.
          */
        int getLineNumber() const
        {
          return lineNumber;
        }

        /** Returns the method name of the caller. */
        const char * getMethodName() const
        {
          return methodName;
        }

        /** Formatted representation of location */
        const std::string getFullInfo() const;

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
      
      
      class LocationFlush : public LocationInfo {
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
    #if defined(_GCC_VER)
      #define LOG4CXX_LOCATION ::log4cxx::spi::location::LocationInfo(__FILE__, \
           __PRETTY_FUNCTION__,                                              \
           __func__,                                                         \
           __LINE__)
      #define LOG4CXX_LOCATION_FLUSH ::log4cxx::spi::location::LocationFlush(__FILE__, \
           __PRETTY_FUNCTION__,                                              \
           __func__,                                                         \
           __LINE__)
    #else
      #if defined(_MSC_VER)
        #define LOG4CXX_LOCATION ::log4cxx::spi::location::LocationInfo(__FILE__, \
             __FUNCSIG__,                                                      \
             __FUNCTION__,                                                     \
             __LINE__)
        #define LOG4CXX_LOCATION_FLUSH ::log4cxx::spi::location::LocationFlush(__FILE__, \
             __FUNCSIG__,                                                      \
             __FUNCTION__,                                                     \
             __LINE__)
      #else
        #define LOG4CXX_LOCATION ::log4cxx::spi::location::LocationInfo(__FILE__, \
             ::log4cxx::spi::location::LocationInfo::NA,                       \
             __func__,                                                         \
             __LINE__)
        #define LOG4CXX_LOCATION_FLUSH ::log4cxx::spi::location::LocationFlush(__FILE__, \
             ::log4cxx::spi::location::LocationInfo::NA,                       \
             __func__,                                                         \
             __LINE__)
      #endif
    #endif
  #endif

#endif //_LOG4CXX_SPI_LOCATION_LOCATIONINFO_H
