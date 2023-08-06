#include "com/foo/config-qt.h"
#include "com/foo/bar.h"
#include <log4cxx-qt/logger.h>

using namespace com::foo;

LoggerPtr Bar::m_logger(getLogger("com.foo.bar"));

void Bar::doIt() {
	LOG4CXX_DEBUG(m_logger, QString("Did it again!") << QString(" - again!"));
}
