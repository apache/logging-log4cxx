#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>

int main( int argc, char **argv)
{
	CppUnit::TextUi::TestRunner runner;

	CppUnit::TestFactoryRegistry &registry =
		CppUnit::TestFactoryRegistry::getRegistry();

	runner.addTest(registry.makeTest());
	
	bool wasSuccessful = true;
	if (argc > 1)
	{
		for (int n = 1; n < argc; n++)
		{
			wasSuccessful = runner.run(argv[n], false) && wasSuccessful;
		}
	}
	else
	{
		bool wasSuccessful = runner.run("", false);
	}

	return wasSuccessful ? EXIT_SUCCESS : EXIT_FAILURE;
}
