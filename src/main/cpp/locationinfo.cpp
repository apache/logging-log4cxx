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

#include <log4cxx/spi/location/locationinfo.h>
#include <log4cxx/helpers/objectoutputstream.h>
#include <log4cxx/helpers/pool.h>
#include "apr_pools.h"
#include "apr_strings.h"

using namespace ::log4cxx::spi;
using namespace log4cxx::helpers;

   /**
     When location information is not available the constant
     <code>NA</code> is returned. Current value of this string
     constant is <b>?</b>.  */
 const char* const LocationInfo::NA = "?";
 const char* const LocationInfo::NA_METHOD = "?::?";

 const LocationInfo& LocationInfo::getLocationUnavailable() {
   static const LocationInfo unavailable;
   return unavailable;
 }

/**
*   Constructor.
*   @remarks Used by LOG4CXX_LOCATION to generate
*       location info for current code site
*/
 LocationInfo::LocationInfo( const char * const fileName1,
              const char * const methodName1,
              int lineNumber1 )
     :  lineNumber( lineNumber1 ),
        fileName( fileName1 ),
        methodName( methodName1 ) {
}

/**
*   Default constructor.
*/
 LocationInfo::LocationInfo()
   : lineNumber( -1 ),
     fileName(LocationInfo::NA),
     methodName(LocationInfo::NA_METHOD) {
}

/**
*   Copy constructor.
*   @param src source location
*/
 LocationInfo::LocationInfo( const LocationInfo & src )
     :  lineNumber( src.lineNumber ),
        fileName( src.fileName ),
        methodName( src.methodName ) {
}

/**
*  Assignment operator.
* @param src source location
*/
 LocationInfo & LocationInfo::operator = ( const LocationInfo & src )
{
  fileName = src.fileName;
  methodName = src.methodName;
  lineNumber = src.lineNumber;
  return * this;
}

/**
 *   Resets location info to default state.
 */
 void LocationInfo::clear() {
  fileName = NA;
  methodName = NA_METHOD;
  lineNumber = -1;
}


/**
 *   Return the file name of the caller.
 *   @returns file name, may be null.
 */
 const char * LocationInfo::getFileName() const
{
  return fileName;
}

/**
  *   Returns the line number of the caller.
  * @returns line number, -1 if not available.
  */
 int LocationInfo::getLineNumber() const
{
  return lineNumber;
}

/** Returns the method name of the caller. */
 const std::string LocationInfo::getMethodName() const
{
    std::string tmp(methodName);
    size_t colonPos = tmp.find("::");
    if (colonPos != std::string::npos) {
      tmp.erase(0, colonPos + 2);
    } else {
      size_t spacePos = tmp.find(' ');
      if (spacePos != std::string::npos) {
        tmp.erase(0, spacePos + 1);
      }
    }
    size_t parenPos = tmp.find('(');
    if (parenPos != std::string::npos) {
      tmp.erase(parenPos);
    }
    return tmp;
}


const std::string LocationInfo::getClassName() const {
        std::string tmp(methodName);
        size_t colonPos = tmp.find("::");
        if (colonPos != std::string::npos) {
           tmp.erase(colonPos);
           size_t spacePos = tmp.find_last_of(' ');
           if (spacePos != std::string::npos) {
               tmp.erase(0, spacePos + 1);
           }
           return tmp;
        }
        tmp.erase(0, tmp.length() );
        return tmp;
}

void LocationInfo::write(ObjectOutputStream& os, Pool& p) const {
    if (lineNumber == -1 && fileName == NA && methodName == NA_METHOD) {
         os.writeByte(ObjectOutputStream::TC_NULL, p);
    } else {
        char prolog[] = {
			0x73, 0x72, 0x00, 0x21, 0x6F, 0x72, 0x67, 0x2E, 
			0x61, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2E, 0x6C, 
			0x6F, 0x67, 0x34, 0x6A, 0x2E, 0x73, 0x70, 0x69, 
			0x2E, 0x4C, 0x6F, 0x63, 0x61, 0x74, 0x69, 0x6F, 
			0x6E, 0x49, 0x6E, 0x66, 0x6F, 0xED, 0x99, 0xBB, 
			0xE1, 0x4A, 0x91, 0xA5, 0x7C, 0x02, 0x00, 0x01, 
			0x4C, 0x00, 0x08, 0x66, 0x75, 0x6C, 0x6C, 0x49, 
			0x6E, 0x66, 0x6F, 0x71, 0x00, 0x7E, 0x00, 0x01, 
			0x78, 0x70, 0x74 };
		os.writeBytes(prolog, sizeof(prolog), p);
        char* line = apr_itoa((apr_pool_t*) p.getAPRPool(), lineNumber);
        //
        //   construct Java-like fullInfo (replace "::" with ".")
        //
        std::string fullInfo(methodName);
        size_t classSep = fullInfo.find("::");
        if (classSep != std::string::npos) {
            fullInfo.replace(classSep, 2, ".");
            size_t space = fullInfo.rfind(' ', classSep);
            if (space != std::string::npos) {
                fullInfo.erase(0, space + 1);
            }
        }
        fullInfo.append(1, '(');
        fullInfo.append(fileName);
        fullInfo.append(1, ':');
        fullInfo.append(line);
        fullInfo.append(1, ')');
        size_t len = fullInfo.length();
        char lenBytes[2];
        lenBytes[1] = len & 0xFF;
        lenBytes[0] = (len >> 8) & 0xFF;
        os.writeBytes(lenBytes, sizeof(lenBytes), p);
        os.writeBytes(fullInfo.data(), len, p);
    }
}


