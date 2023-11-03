/*	Mocked CFString implementation
*/
#include "CoreFoundation/CFString.h"
#include <apr_pools.h>
#include <exception>
#include <log4cxx/helpers/widelife.h>

namespace {
int throw_out_of_mem(int status)
{
	throw std::bad_alloc();
	return status;
}
apr_pool_t* getStringPool()
{
	struct cfstring_pool
	{
		apr_pool_t* ptr = 0;
		cfstring_pool()
		{
			apr_pool_create_core_ex(&ptr, throw_out_of_mem, NULL);
		}
		~cfstring_pool()
		{
			apr_pool_destroy(ptr);
		}
	};
	static LOG4CXX_NS::helpers::WideLife<cfstring_pool> pool;
	return pool.ptr;
}
} // namespace

extern "C" {

CFRange CFRangeMake(CFIndex loc, CFIndex len) {
	CFRange result;
	result.location = loc;
	result.length = len;
	return result;
}

CFIndex CFStringGetLength(CFStringRef theString) {
	UniChar* data = (UniChar*)theString;
	CFIndex result = 0;
	while (data[result])
		++result;
	return result;
}
void CFStringGetCharacters(CFStringRef theString, CFRange range, UniChar *buffer) {
	UniChar* data = (UniChar*)theString;
	CFIndex index = 0;
	while (index < range.length) {
		*buffer = data[range.location + index];
		++index;
		++buffer;
	}
}
CFStringRef CFStringCreateWithCharacters(CFAllocatorRef alloc, const UniChar *chars, CFIndex numChars) {
	UniChar* result = (UniChar*)apr_palloc(getStringPool(), (numChars + 1) * sizeof(UniChar));
	result[numChars] = 0;
	for (UniChar* p = result; 0 < numChars; --numChars)
		*p++ = *chars++;
	return (CFStringRef)result;
}
CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding) {
	UniChar* result = (UniChar*)apr_palloc(getStringPool(), (strlen(cStr) + 1) * sizeof(UniChar));
	for (UniChar *p = result; *p++ = *cStr++;)
		;
	return (CFStringRef)result;
}

} // extern "C"
