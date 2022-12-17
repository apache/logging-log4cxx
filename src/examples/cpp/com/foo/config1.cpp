#include "com/foo/config.h"
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/logmanager.h>

namespace com { namespace foo {

auto getLogger(const std::string& name) -> LoggerPtr {
	static struct log4cxx_initializer {
		log4cxx_initializer() {
			// Set up a simple configuration that logs on the console.
			log4cxx::BasicConfigurator::configure();
		}
		~log4cxx_initializer() {
			log4cxx::LogManager::shutdown();
		}
	} initAndShutdown;
	return name.empty()
		? log4cxx::LogManager::getRootLogger()
		: log4cxx::LogManager::getLogger(name);
}

} } // namespace com::foo
