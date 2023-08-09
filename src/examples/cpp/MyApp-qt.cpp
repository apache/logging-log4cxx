#include <QCoreApplication>
#include "com/foo/config-qt.h"
#include "com/foo/bar.h"

int main(int argc, char **argv) {
	int result = EXIT_SUCCESS;
	QCoreApplication app(argc, argv);
	com::foo::ConfigureLogging();
	try {
		auto logger = com::foo::getLogger("MyApp");
		LOG4CXX_INFO(logger, QString("Message %1").arg(1));
		com::foo::Bar bar;
		bar.doIt();
		LOG4CXX_INFO(logger, QString("Message %1").arg(2));
	}
	catch(std::exception&) {
		result = EXIT_FAILURE;
	}
	return result;
}
