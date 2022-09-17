#include <log4cxx/logger.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/asyncappender.h>
#include <fmt/format.h>
#include <benchmark/benchmark.h>
#include <thread>

using namespace log4cxx;

class NullWriterAppender : public AppenderSkeleton
{
public:
	DECLARE_LOG4CXX_OBJECT(NullWriterAppender)
	BEGIN_LOG4CXX_CAST_MAP()
	LOG4CXX_CAST_ENTRY(NullWriterAppender)
	LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
	END_LOG4CXX_CAST_MAP()

	NullWriterAppender() {}

	virtual void close() {}

	virtual bool requiresLayout() const
	{
		return true;
	}

	virtual void append(const spi::LoggingEventPtr& event, helpers::Pool& p)
	{
		// This gets called whenever there is a valid event for our appender.
	}

	virtual void activateOptions(helpers::Pool& /* pool */)
	{
		// Given all of our options, do something useful(e.g. open a file)
	}

	virtual void setOption(const LogString& option, const LogString& value)
	{
	}
};

IMPLEMENT_LOG4CXX_OBJECT(NullWriterAppender)

#if defined(LOG4CXX_VERSION_MINOR) && 11 < LOG4CXX_VERSION_MINOR
LOG4CXX_PTR_DEF(NullWriterAppender);
#else
#define LOG4CXX_HAS_FMT 0
template class log4cxx::helpers::ObjectPtrT<NullWriterAppender>;
typedef log4cxx::helpers::ObjectPtrT<NullWriterAppender> NullWriterAppenderPtr;
#endif

class benchmarker : public ::benchmark::Fixture
{
public:
	LoggerPtr console;
	void SetUp(const ::benchmark::State& state)
	{
		std::setlocale( LC_ALL, "" ); /* Set locale for C functions */
		std::locale::global(std::locale("")); /* set locale for C++ functions */
		console = Logger::getLogger( "console" );
		console->setAdditivity( false );
		PatternLayoutPtr pattern( new PatternLayout() );
		pattern->setConversionPattern( LOG4CXX_STR("%m%n") );

		ConsoleAppenderPtr consoleWriter( new ConsoleAppender );
		consoleWriter->setLayout( pattern );
		consoleWriter->setTarget( LOG4CXX_STR("System.out") );
		helpers::Pool p;
		consoleWriter->activateOptions(p);
		console->addAppender( consoleWriter );
	}

	void TearDown(const ::benchmark::State& state)
	{
	}

	static LoggerPtr resetLogger()
	{
		LoggerPtr logger = Logger::getLogger( LOG4CXX_STR("bench_logger") );

		logger->removeAllAppenders();
		logger->setAdditivity( false );
		logger->setLevel( Level::getInfo() );

		PatternLayoutPtr pattern(new PatternLayout);
		pattern->setConversionPattern( LOG4CXX_STR("%m%n") );

		NullWriterAppenderPtr nullWriter(new NullWriterAppender);
		nullWriter->setLayout( pattern );

		logger->addAppender( nullWriter );

		return logger;
	}

	static int threadCount()
	{
		auto threadCount = helpers::StringHelper::toInt
			(helpers::OptionConverter::getSystemProperty
				(LOG4CXX_STR("LOG4CXX_BENCHMARK_THREAD_COUNT"), LOG4CXX_STR("")));
		if (threadCount <= 0)
			threadCount = std::thread::hardware_concurrency() - 2;
		return threadCount;
	}

	static double warmUpSeconds()
	{
		auto milliseconds = helpers::StringHelper::toInt
			(helpers::OptionConverter::getSystemProperty
				(LOG4CXX_STR("LOG4CXX_BENCHMARK_WARM_UP_MILLISECONDS"), LOG4CXX_STR("")));
		if (milliseconds <= 0)
			milliseconds = 100;
		return milliseconds / 1000;
	}

};

static void ResetLogger(const benchmark::State& state)
{
	benchmarker::resetLogger();
}

BENCHMARK_DEFINE_F(benchmarker, logDisabledTrace)(benchmark::State& state)
{
	LoggerPtr logger = Logger::getLogger( LOG4CXX_STR("bench_logger") );
	logger->setLevel(Level::getDebug());

	for (auto _ : state)
	{
		LOG4CXX_TRACE( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logDisabledTrace)->Name("Logging disabled trace")->MinWarmUpTime(benchmarker::warmUpSeconds());
BENCHMARK_REGISTER_F(benchmarker, logDisabledTrace)->Name("Logging disabled trace")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logDisabledDebug)(benchmark::State& state)
{
	LoggerPtr logger = Logger::getLogger(LOG4CXX_STR("bench_logger"));
	logger->setLevel(Level::getInfo());

	for (auto _ : state)
	{
		LOG4CXX_DEBUG(logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logDisabledDebug)->Name("Logging disabled debug");

BENCHMARK_DEFINE_F(benchmarker, logStaticString)(benchmark::State& state)
{
	LoggerPtr logger = resetLogger();

	for (auto _ : state)
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logStaticString)->Name("Logging info static string");

BENCHMARK_DEFINE_F(benchmarker, logEnabledDebug)(benchmark::State& state)
{
	LoggerPtr logger = resetLogger();
	logger->setLevel( Level::getDebug() );

	for (auto _ : state)
	{
		LOG4CXX_DEBUG( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logEnabledDebug)->Name("Logging enabled debug static string");

BENCHMARK_DEFINE_F(benchmarker, logEnabledTrace)(benchmark::State& state)
{
	LoggerPtr logger = resetLogger();
	logger->setLevel( Level::getTrace() );

	for (auto _ : state)
	{
		LOG4CXX_DEBUG( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logEnabledTrace)->Name("Logging enabled trace static string");

#if LOG4CXX_HAS_FMT
BENCHMARK_DEFINE_F(benchmarker, logStaticStringFMT)(benchmark::State& state)
{
	LoggerPtr logger = resetLogger();

	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT(logger, "This is a static string to see what happens");
	}
}
BENCHMARK_REGISTER_F(benchmarker, logStaticStringFMT)->Name("Logging static string with FMT");

BENCHMARK_DEFINE_F(benchmarker, logIntValueFMT)(benchmark::State& state)
{
	LoggerPtr logger = resetLogger();
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT( logger, "Hello logger: msg number {}", ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueFMT)->Name("Logging int value with FMT");

BENCHMARK_DEFINE_F(benchmarker, logIntValueFMTMultithreaded)(benchmark::State& state)
{
	LoggerPtr logger = Logger::getLogger( LOG4CXX_STR("bench_logger") );

	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT( logger, "Hello logger: msg number {}", ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueFMTMultithreaded)->Name("Logging int value with FMT")->Threads(benchmarker::threadCount())->Setup(ResetLogger);
#endif

BENCHMARK_DEFINE_F(benchmarker, logIntValueStream)(benchmark::State& state)
{
	LoggerPtr logger = resetLogger();
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( logger, "Hello logger: msg number " << ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueStream)->Name("Logging int value with std::ostream");

BENCHMARK_DEFINE_F(benchmarker, logIntValueStreamMultithreaded)(benchmark::State& state)
{
	LoggerPtr logger = Logger::getLogger( LOG4CXX_STR("bench_logger") );

	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( logger, "Hello logger: msg number " << ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueStreamMultithreaded)->Name("Logging int value with std::ostream")->Threads(benchmarker::threadCount())->Setup(ResetLogger);

template <class ...Args>
void logWithConversionPattern(benchmark::State& state, Args&&... args)
{
    auto args_tuple = std::make_tuple(std::move(args)...);
	LogString conversionPattern = std::get<0>(args_tuple);
	LoggerPtr logger = Logger::getLogger( LOG4CXX_STR("bench_logger") );

	logger->removeAllAppenders();
	logger->setAdditivity( false );
	logger->setLevel( Level::getInfo() );

	PatternLayoutPtr pattern(new PatternLayout);
	pattern->setConversionPattern( conversionPattern );

	NullWriterAppenderPtr nullWriter(new NullWriterAppender);
	nullWriter->setLayout( pattern );

	logger->addAppender( nullWriter );

	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("Hello logger: msg number ") << ++x);
	}
}
BENCHMARK_CAPTURE(logWithConversionPattern, NoFormat, LOG4CXX_STR("%m%n"))->Name("NoFormat pattern: %m%n");
BENCHMARK_CAPTURE(logWithConversionPattern, DateOnly, LOG4CXX_STR("[%d] %m%n"))->Name("DateOnly pattern: [%d] %m%n");
BENCHMARK_CAPTURE(logWithConversionPattern, DateClassLevel, LOG4CXX_STR("[%d] [%c] [%p] %m%n"))->Name("DateClassLevel pattern: [%d] [%c] [%p] %m%n");

BENCHMARK_DEFINE_F(benchmarker, logToAsyncAppender)(benchmark::State& state)
{
	LoggerPtr logger = Logger::getLogger( LOG4CXX_STR("bench_logger") );
	logger->removeAllAppenders();
	logger->setAdditivity( false );
	logger->setLevel( Level::getInfo() );

	PatternLayoutPtr pattern(new PatternLayout);
	pattern->setConversionPattern(LOG4CXX_STR("%m%n"));

	NullWriterAppenderPtr nullWriter(new NullWriterAppender);
	nullWriter->setLayout( pattern );
	AsyncAppenderPtr asyncAppender = AsyncAppenderPtr(new AsyncAppender());
	asyncAppender->addAppender(nullWriter);
	asyncAppender->setBufferSize(5);
	helpers::Pool p;
	asyncAppender->activateOptions(p);
	logger->addAppender(asyncAppender);

	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("Hello logger: msg number ") << ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logToAsyncAppender)->Name("Async pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logToAsyncAppender)->Name("Async pattern: %m%n")->Threads(benchmarker::threadCount())->Setup(ResetLogger);

BENCHMARK_MAIN();

