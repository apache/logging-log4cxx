#ifndef COM_FOO_BAR_H_
#define COM_FOO_BAR_H_
#include "com/foo/config.h"
namespace com { namespace foo {

class Bar {
    static LoggerPtr m_logger;
    public:
        void doIt();
};

} } // namespace com::foo
#endif // COM_FOO_BAR_H_
