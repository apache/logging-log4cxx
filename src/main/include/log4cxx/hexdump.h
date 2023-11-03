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

#ifndef LOG4CXX_HEXDUMP_H
#define LOG4CXX_HEXDUMP_H

#include <log4cxx/logstring.h>
#include <stdint.h>

namespace LOG4CXX_NS
{

enum class HexdumpFlags : uint32_t{
	None,
	AddStartingNewline = (0x01 << 0),
	AddEndingNewline = (0x01 << 1),
	AddNewline = AddStartingNewline | AddEndingNewline,
};

inline bool operator&(HexdumpFlags a, HexdumpFlags b){
	return !!(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline HexdumpFlags operator|(HexdumpFlags a, HexdumpFlags b){
	return static_cast<HexdumpFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * Hexdump the given bytes and return a LogString with the dumped bytes.
 *
 * Sample output:
 * 00000000  0a 20 20 20 20 20 20 20  20 20 20 20 20 20 20 20  |.               |
 *
 * @param bytes A pointer to the bytes to dump
 * @param len How many bytes to dump
 * @param flags Flags to control the output format of the hexdump
 * @return A LogString with the hexdump output
 */
LOG4CXX_EXPORT
LogString hexdump(const void* bytes, uint32_t len, HexdumpFlags flags = HexdumpFlags::None);

}
#endif // LOG4CXX_HEXDUMP_H
