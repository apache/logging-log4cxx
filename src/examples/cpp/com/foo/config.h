#ifndef COM_FOO_CONFIG_H_
#define COM_FOO_CONFIG_H_
#include <log4cxx/logger.h>
namespace com { namespace foo {

using LoggerPtr = log4cxx::LoggerPtr;
extern auto getLogger(const std::string& name = std::string()) -> LoggerPtr;

} } // namespace com::foo
#endif // COM_FOO_CONFIG_H_
