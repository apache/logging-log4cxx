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

 #include <log4cxx/spi/location/locationinfo.h>
 #include <sstream>

 using namespace ::log4cxx::spi::location;
   /**
     When location information is not available the constant
     <code>NA</code> is returned. Current value of this string
     constant is <b>?</b>.  */
 const char* const LocationInfo::NA = "?";

/**
*   Constructor.
*   @remarks Used by LOG4CXX_LOCATION to generate
*       location info for current code site
*/
 LocationInfo::LocationInfo( const char * const fileName,
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
 LocationInfo::LocationInfo()
   : fileName(LocationInfo::NA),
     className(LocationInfo::NA),
     methodName(LocationInfo::NA),
     lineNumber(-1) {
}

/**
*   Copy constructor.
*   @param src source location
*/
 LocationInfo::LocationInfo( const LocationInfo & src )
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
 LocationInfo & LocationInfo::operator = ( const LocationInfo & src )
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
 void LocationInfo::clear() {
  fileName = NA;
  className = NA;
  methodName = NA;
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
 const char * LocationInfo::getMethodName() const
{
  return methodName;
}


const std::string LocationInfo::getClassName() const {
	if (className == NULL) {
		return NA;
	}
	if (strchr(className, ':') == NULL) {
		return className;
	}
	std::string tmp(className);
	size_t colonPos = tmp.find("::");
	if (colonPos != std::string::npos) {
		size_t spacePos = tmp.find_last_of(' ', colonPos);
		if (spacePos != std::string::npos) {
			tmp.erase(colonPos);
			tmp.erase(0, spacePos + 1);
		}
	}
	return tmp;
}

const std::string LocationInfo::getFullInfo() const {
	std::ostringstream os;
	os << getClassName()
	   << '.'
	   << getMethodName()
	   << '('
	   << getFileName()
	   << ':'
	   << getLineNumber()
	   << ')';
	return os.str();
}
