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

#include "xmlfilenamefilter.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

XMLFilenameFilter::XMLFilenameFilter(const std::string& actual, const std::string& expected) {
    std::string pattern(" file=\"");
    std::string replacement(" file=\"");
	std::string filename(actual);
	size_t backslash = filename.rfind('\\', filename.length() - 1);
	while (backslash != std::string::npos) {
		filename.replace(backslash, 1, "\\\\", 2);
		if (backslash == 0) {
			backslash = std::string::npos;
		} else {
		    backslash = filename.rfind('\\', backslash - 1);
		}
	}
    pattern += filename;
    pattern += "\"";

    replacement += expected;
    replacement += "\"";
    patterns.push_back( PatternReplacement(pattern, replacement) );
}
