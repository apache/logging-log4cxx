#ifndef BOOST_STD_CONFIGURATION_H
#define BOOST_STD_CONFIGURATION_H

#cmakedefine01 STD_FILESYSTEM_FOUND
#cmakedefine01 Boost_FILESYSTEM_FOUND
#cmakedefine01 STD_EXPERIMENTAL_FILESYSTEM_FOUND

#if STD_FILESYSTEM_FOUND
#include <filesystem>
namespace ${NAMESPACE_ALIAS} {
namespace filesystem {
    typedef std::filesystem::path path;
}
}
#elif STD_EXPERIMENTAL_FILESYSTEM_FOUND
#include <experimental/filesystem>
namespace ${NAMESPACE_ALIAS} {
namespace filesystem {
    typedef std::experimental::filesystem::path path;
}
}
#elif Boost_FILESYSTEM_FOUND
#include <boost/filesystem.hpp>
namespace ${NAMESPACE_ALIAS} {
namespace filesystem {
    typedef boost::filesystem::path path;
}
}
#endif

#endif /* BOOST_STD_CONFIGURATION_H */
