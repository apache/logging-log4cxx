#ifndef LOG4CXX_MAKE_UNIQUE_H
#define LOG4CXX_MAKE_UNIQUE_H

#cmakedefine01 STD_MAKE_UNIQUE_FOUND

#if !STD_MAKE_UNIQUE_FOUND
namespace std{
template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args )
{
    return std::unique_ptr<T>( new T( std::forward<Args>(args)... ) );
}
}
#endif

#endif /* LOG4CXX_MAKE_UNIQUE_H */
