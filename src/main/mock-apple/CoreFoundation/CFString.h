/*	Mocked CFString.h
*/
#include <stdint.h>
#if !defined(__COREFOUNDATION_CFSTRING__)
#define __COREFOUNDATION_CFSTRING__ 1
extern "C" {
typedef unsigned short UniChar;
typedef long CFIndex;
typedef struct __CFRange {
	CFIndex location;
	CFIndex length;
} CFRange;
typedef const struct __CFString* CFStringRef;
typedef const struct __CFAllocator* CFAllocatorRef;
typedef uint32_t CFStringEncoding;
CFRange CFRangeMake(CFIndex loc, CFIndex len);
CFIndex CFStringGetLength(CFStringRef theString);
void CFStringGetCharacters(CFStringRef theString, CFRange range, UniChar *buffer);
CFStringRef CFStringCreateWithCharacters(CFAllocatorRef alloc, const UniChar *chars, CFIndex numChars);
CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding);
#define kCFAllocatorDefault 0
#define CFSTR(cStr) CFStringCreateWithCString(kCFAllocatorDefault, cStr, 0)
}
#endif /* ! __COREFOUNDATION_CFSTRING__ */
