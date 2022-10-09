#include <log4cxx/logger.h>

namespace UserLib
{

extern log4cxx::LoggerPtr getLogger(const std::string& name = std::string());

} // namespace UserLib
