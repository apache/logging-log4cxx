#ifdef __has_include                           // Check if __has_include is present
#  if __has_include(<optional>)                // Check for a standard version
#    include <optional>
#    if defined(__cpp_lib_optional)            // C++ >= 17
namespace LOG4CXX_NS { template< class T > using Optional = std::optional<T>; }
#define LOG4CXX_HAS_STD_OPTIONAL 1
#endif
#  elif __has_include(<experimental/optional>) // Check for an experimental version
#    include <experimental/optional>
namespace LOG4CXX_NS { template< class T > using Optional = std::experimental::optional<T>; }
#define LOG4CXX_HAS_STD_OPTIONAL 1
#  elif __has_include(<boost/optional.hpp>)    // Try with an external library
#    include <boost/optional.hpp>
namespace LOG4CXX_NS { template< class T > using Optional = boost::optional<T>; }
#define LOG4CXX_HAS_STD_OPTIONAL 1
#  else                                        // Not found at all
#define LOG4CXX_HAS_STD_OPTIONAL 0
#  endif
#endif

#if !LOG4CXX_HAS_STD_OPTIONAL // Implement a minimal Optional?
namespace LOG4CXX_NS
{
	template< class T >
class Optional : private std::pair<bool, T>
{
	using BaseType = std::pair<bool, T>;
public:
	Optional() : BaseType(false, T()) {}
	Optional& operator=(const T& value)
	{
		this->first = true;
		this->second = value;
		return *this;
	}
	bool has_value() const { return this->first; }
	const T& value() const { return this->second; }
};
} // namespace LOG4CXX_NS
#endif
