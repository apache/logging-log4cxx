#ifndef COM_FOO_CONFIG_QT_H_
#define COM_FOO_CONFIG_QT_H_
#include <log4cxx-qt/logger.h>

/// Methods specific to foo.com
namespace com { namespace foo {

// Provide the name of the configuration file to Log4cxx.
void ConfigureLogging();

/// The logger pointer we use
using LoggerPtr = log4cxx::LoggerPtr;

/// Retrieve the \c name logger pointer.
extern auto getLogger(const QString& name) -> LoggerPtr;

/// Retrieve the \c name logger pointer.
extern auto getLogger(const char* name = NULL) -> LoggerPtr;

} } // namespace com::foo
#endif // COM_FOO_CONFIG_QT_H_
