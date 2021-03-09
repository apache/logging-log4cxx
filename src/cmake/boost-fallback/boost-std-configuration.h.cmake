#ifndef BOOST_STD_CONFIGURATION_H
#define BOOST_STD_CONFIGURATION_H

#cmakedefine01 STD_SHARED_MUTEX_FOUND
#cmakedefine01 Boost_SHARED_MUTEX_FOUND

#if STD_SHARED_MUTEX_FOUND
#include <shared_mutex>
namespace ${NAMESPACE_ALIAS} {
    typedef std::shared_mutex shared_mutex;
    template <typename T>
    using shared_lock = std::shared_lock<T>;
}
#elif Boost_SHARED_MUTEX_FOUND
#include <boost/thread/shared_mutex.hpp>
namespace ${NAMESPACE_ALIAS} {
    typedef boost::shared_mutex shared_mutex;
    template <typename T>
    using shared_lock = boost::shared_lock<T>;
}
#endif

#endif /* BOOST_STD_CONFIGURATION_H */
