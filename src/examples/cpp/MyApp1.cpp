#include <log4cxx/logger.h>
#include <log4cxx/basicconfigurator.h>

static auto logger = log4cxx::Logger::getLogger("MyApp");

void foo() {
	// Get a logger that is a child of the statically declared logger
	auto fooLogger = log4cxx::Logger::getLogger("MyApp.foo");
	LOG4CXX_TRACE(fooLogger, "Doing foo at trace level");
	LOG4CXX_DEBUG(fooLogger, "Doing foo at debug level");
	LOG4CXX_INFO(fooLogger, "Doing foo at info level");
	LOG4CXX_WARN(fooLogger, "Doing foo at warn level");
	LOG4CXX_ERROR(fooLogger, "Doing foo at error level");
	LOG4CXX_FATAL(fooLogger, "Doing foo at fatal level");
}

int main(int argc, char **argv) {
	// Log to standard output.
	log4cxx::BasicConfigurator::configure();
	LOG4CXX_INFO(logger, "Entering application.");
	foo();
	LOG4CXX_INFO(logger, "Exiting application.");
	return EXIT_SUCCESS;
}
