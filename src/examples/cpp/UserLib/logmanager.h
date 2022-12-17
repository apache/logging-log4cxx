#include <log4cxx/logger.h>

namespace UserLib
{

    extern auto
getLogger(const std::string& name = std::string()) -> log4cxx::LoggerPtr;

} // namespace UserLib
