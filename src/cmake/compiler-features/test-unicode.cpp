/* Prevent error C2491: 'std::numpunct<_Elem>::id': definition of dllimport static data member not allowed */
#if defined(_MSC_VER)
#define __FORCE_INSTANCE
#endif
#include <string>
#include <sstream>

using UniChar = unsigned short;
using StringType = std::basic_string<UniChar>;
using StreamType = std::basic_ostringstream<UniChar>;
int main()
{
	StringType str;
	StreamType ss;
    ss << str;
    return 0;
}
