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

#include <log4cxx/log4cxx.h>
/* Prevent error C2491: 'std::numpunct<_Elem>::id': definition of dllimport static data member not allowed */
#if defined(_MSC_VER) && (LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR)
#define __FORCE_INSTANCE
#endif
#include <log4cxx/hexdump.h>
#include <log4cxx/log4cxx.h>
#include <sstream>
#include <ios>
#include <iomanip>
#include <cctype>

using namespace LOG4CXX_NS;

typedef std::basic_stringstream<logchar> LogStream;

LogString LOG4CXX_NS::hexdump(const void* bytes, uint32_t len, HexdumpFlags flags){
	LogString ret;
	const uint8_t* bytes_u8 = static_cast<const uint8_t*>(bytes);
	LogStream sstream;
#if LOG4CXX_LOGCHAR_IS_WCHAR
	const wchar_t fill_char = L'0';
	const wchar_t space_fill_char = L' ';
#else
	const logchar fill_char = '0';
	const logchar space_fill_char = ' ';
#endif

	if(flags & HexdumpFlags::AddStartingNewline){
		sstream << LOG4CXX_EOL;
	}

	for(uint32_t offset = 0; offset < len; offset += 16){
		if(offset != 0){
			sstream << LOG4CXX_EOL;
		}

		// Print out the offset
		sstream << std::hex << std::setw(8) << std::setfill(fill_char) << offset << std::resetiosflags(std::ios_base::fmtflags(0));

		sstream << std::setw(0) << LOG4CXX_STR("  ");

		// Print out the first 8 bytes
		for(int byte = 0; byte < 8; byte++){
			if(offset + byte >= len){
				sstream << LOG4CXX_STR("  ");
				if(byte != 8){
					sstream << LOG4CXX_STR(" ");
				}
				continue;
			}

			sstream << std::hex << std::setw(2) << std::setfill(fill_char) << static_cast<int>(bytes_u8[offset + byte]) << std::resetiosflags(std::ios_base::fmtflags(0));
			sstream << std::setfill(space_fill_char);
			if(byte != 8){
				sstream << LOG4CXX_STR(" ");
			}
		}

		sstream << LOG4CXX_STR(" ");

		// Print out the last 8 bytes
		for(int byte = 8; byte < 16; byte++){
			if(offset + byte >= len){
				sstream << LOG4CXX_STR("  ");
				if(byte != 15){
					sstream << LOG4CXX_STR(" ");
				}
				continue;
			}

			sstream << std::hex << std::setw(2) << std::setfill(fill_char) << static_cast<int>(bytes_u8[offset + byte]) << std::resetiosflags(std::ios_base::fmtflags(0));
			if(byte != 15){
				sstream << LOG4CXX_STR(" ");
			}
		}

		// Print out the ASCII text
		sstream << LOG4CXX_STR("  |");
		for(int byte = 0; byte < 16; byte++){
			if(offset + byte >= len){
				break;
			}
			if(std::isprint(bytes_u8[offset + byte])){
				logchar to_append = bytes_u8[offset + byte];
				sstream << to_append;
			}else{
				sstream << LOG4CXX_STR(".");
			}
		}
		sstream << LOG4CXX_STR("|");
	}

	if(flags & HexdumpFlags::AddEndingNewline){
		sstream << LOG4CXX_EOL;
	}

	return sstream.str();
}
