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
