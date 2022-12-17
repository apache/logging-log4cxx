#ifndef COM_FOO_CONFIG_H_
#define COM_FOO_CONFIG_H_
#include <log4cxx/logger.h>

/// Types specific to foo.com
namespace com { namespace foo {

/// The logger pointer we use
using LoggerPtr = log4cxx::LoggerPtr;

/// Retrieve the \c name logger pointer.
/// Configure Log4cxx on the first call.
extern auto getLogger(const std::string& name = std::string()) -> LoggerPtr;

} } // namespace com::foo
#endif // COM_FOO_CONFIG_H_
