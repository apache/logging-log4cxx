#ifdef __has_include                           // Check if __has_include is present
#  if __has_include(<optional>)                // Check for a standard library
#    include <optional>
namespace LOG4CXX_NS { template< class T > using Optional = std::optional<T>; }
#  elif __has_include(<experimental/optional>) // Check for an experimental version
#    include <experimental/optional>
namespace LOG4CXX_NS { template< class T > using Optional = std::experimental::optional<T>; }
#  elif __has_include(<boost/optional.hpp>)    // Try with an external library
#    include <boost/optional.hpp>
namespace LOG4CXX_NS { template< class T > using Optional = boost::optional<T>; }
#  else                                        // Not found at all
#     error "Missing <optional>"
#  endif
#endif