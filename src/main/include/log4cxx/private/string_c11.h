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

#ifndef LOG4CXX_STRING_C11_H
#define LOG4CXX_STRING_C11_H
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#include <stdint.h> // RSIZE_MAX

#if !defined(__STDC_LIB_EXT1__) && !defined(__STDC_SECURE_LIB__)
static size_t strnlen_s( const char *str, size_t strsz )
{
    size_t result = 0;
    if (!str)
        ;
    else while (*str++ != 0 && result < strsz)
		++result;
	return result;
}
static int strcat_s(char* destArg, size_t destsz, const char* src)
{
	if (!src || !destArg || RSIZE_MAX < destsz)
		return -1;
	char* dest = destArg;
	size_t index = 0;
	while (*dest && index < destsz)
		++index, ++dest;
	while (*src && index < destsz)
	{
		*dest++ = *src++;
		++index;
	}
	if (*src)
	{
		*destArg = 0;
		return -2;
	}
	return 0;
}
#endif

#endif /* LOG4CXX_STRING_C11_H */
