#include "com/foo/bar.h"

using namespace com::foo;

LoggerPtr Bar::m_logger(getLogger("com.foo.bar"));

void Bar::doIt() {
	LOG4CXX_DEBUG(m_logger, "Did it again!");
}
