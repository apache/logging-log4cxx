/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/
 
#ifndef _LOG4CXX_HELPERS_STRICTMATH_H
#define _LOG4CXX_HELPERS_STRICTMATH_H
 
#include <log4cxx/config.h>
 
namespace log4cxx
{
	namespace helpers
	{
		/**
		The class StrictMath contains methods for performing basic numeric
		operations
		*/
		class StrictMath
		{
		public:
			template<typename _type> static inline const _type& 
				min(const _type& a, const _type& b)
			{
				return (a < b) ? a : b;
			}
			
			template<typename _type> static inline const _type& 
				max(const _type& a, const _type& b)
			{
				return (a > b) ? a : b;
			}
		}; // class StrictMath
	}; // namespace helpers
}; // namespace log4cx

#endif //_LOG4CXX_HELPERS_STRICTMATH_H
