#ifndef LOG4CXX_FILESYSTEM_HELPER_HDR_
#define LOG4CXX_FILESYSTEM_HELPER_HDR_

#include <log4cxx/log4cxx.h>

#if STD_FILESYSTEM_FOUND
#include <filesystem>
namespace LOG4CXX_NS
{
namespace filesystem { using path = std::filesystem::path; }
#if LOG4CXX_FILE_IS_FILESYSTEM_PATH
using File = std::filesystem::path;
using FileErrorCode = std::error_code;
#endif
}
#elif STD_EXPERIMENTAL_FILESYSTEM_FOUND
#include <experimental/filesystem>
namespace LOG4CXX_NS
{
namespace filesystem { using path = std::experimental::filesystem::path; }
#if LOG4CXX_FILE_IS_FILESYSTEM_PATH
using File = std::experimental::filesystem::path;
using FileErrorCode = std::error_code;
#endif
}
#elif Boost_FILESYSTEM_FOUND
#include <boost/filesystem.hpp>
namespace LOG4CXX_NS
{
namespace filesystem { using path = boost::filesystem::path; }
#if LOG4CXX_FILE_IS_FILESYSTEM_PATH
using File = boost::filesystem::path;
using FileErrorCode = boost::system::error_code;
#endif
}
#endif

#endif // LOG4CXX_FILESYSTEM_HELPER_HDR_
