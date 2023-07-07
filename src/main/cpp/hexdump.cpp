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
#include <log4cxx/hexdump.h>
#include <sstream>
#include <ios>
#include <iomanip>

using namespace log4cxx;

typedef std::basic_stringstream<logchar> LogStream;

LogString log4cxx::hexdump(void* bytes, uint32_t len, HexdumpFlags flags){
	LogString ret;
	uint8_t* bytes_u8 = static_cast<uint8_t*>(bytes);
	LogStream sstream;

	if(flags & HexdumpFlags::AddStartingNewline){
		sstream << LOG4CXX_EOL;
	}

	for(uint32_t offset = 0; offset < len; offset += 16){
		if(offset != 0){
			sstream << LOG4CXX_EOL;
		}

		// Print out the offset
		sstream << std::hex << std::setw(8) << std::setfill('0') << offset << std::resetiosflags(std::ios_base::fmtflags(0));

		sstream << std::setw(0) << LOG4CXX_STR("  ");

		// Print out the first 8 bytes
		for(int byte = 0; byte < 8; byte++){
			if(offset + byte > len){
				sstream << LOG4CXX_STR("  ");
				if(byte != 8){
					sstream << LOG4CXX_STR(" ");
				}
				continue;
			}

			sstream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes_u8[offset + byte]) << std::resetiosflags(std::ios_base::fmtflags(0));
			sstream << std::setfill(' ');
			if(byte != 8){
				sstream << LOG4CXX_STR(" ");
			}
		}

		sstream << LOG4CXX_STR(" ");

		// Print out the last 8 bytes
		for(int byte = 8; byte < 16; byte++){
			if(offset + byte > len){
				sstream << LOG4CXX_STR("  ");
				if(byte != 15){
					sstream << LOG4CXX_STR(" ");
				}
				continue;
			}

			sstream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes_u8[offset + byte]) << std::resetiosflags(std::ios_base::fmtflags(0));
			if(byte != 15){
				sstream << LOG4CXX_STR(" ");
			}
		}

		// Print out the ASCII text
		sstream << LOG4CXX_STR("  |");
		for(int byte = 0; byte < 16; byte++){
			if(offset + byte > len){
				break;
			}
			if(std::isprint(bytes_u8[offset + byte])){
				sstream << bytes_u8[offset + byte];
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
