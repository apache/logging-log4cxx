#include <log4cxx/logger.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/appenderskeleton.h>
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

	void close() override {}

	bool requiresLayout() const override
	{
		return true;
	}

	void append(const spi::LoggingEventPtr& event, helpers::Pool& p) override
	{
		// This gets called whenever there is a valid event for our appender.
	}

	void activateOptions(helpers::Pool& /* pool */) override
	{
		// Given all of our options, do something useful(e.g. open a file)
	}

	void setOption(const LogString& option, const LogString& value) override
	{
	}
};

IMPLEMENT_LOG4CXX_OBJECT(NullWriterAppender)

#if defined(LOG4CXX_VERSION_MINOR) && (0 < LOG4CXX_VERSION_MAJOR || 11 < LOG4CXX_VERSION_MINOR)
LOG4CXX_PTR_DEF(NullWriterAppender);
#else
#define LOG4CXX_HAS_FMT 0
template class log4cxx::helpers::ObjectPtrT<NullWriterAppender>;
typedef log4cxx::helpers::ObjectPtrT<NullWriterAppender> NullWriterAppenderPtr;
#endif

class benchmarker : public ::benchmark::Fixture
{
public:
	LoggerPtr m_logger;
	void SetupLogger()
	{
		m_logger = Logger::getLogger(LOG4CXX_STR("bench_logger"));

		m_logger->removeAllAppenders();
		m_logger->setAdditivity(false);
		m_logger->setLevel(Level::getInfo());

		PatternLayoutPtr pattern(new PatternLayout);
		pattern->setConversionPattern(LOG4CXX_STR("%m%n"));

		NullWriterAppenderPtr nullWriter(new NullWriterAppender);
		nullWriter->setName(LOG4CXX_STR("NullWriterAppender"));
		nullWriter->setLayout(pattern);

		m_logger->addAppender(nullWriter);
	}

	void SetUp(const ::benchmark::State& state)
	{
		std::setlocale( LC_ALL, "" ); /* Set locale for C functions */
		std::locale::global(std::locale("")); /* set locale for C++ functions */
		SetupLogger();
	}

	void TearDown(const ::benchmark::State& state)
	{
	}

	static int threadCount()
	{
		auto threadCount = helpers::StringHelper::toInt
			(helpers::OptionConverter::getSystemProperty
				(LOG4CXX_STR("LOG4CXX_BENCHMARK_THREAD_COUNT"), LOG4CXX_STR("0")));
		if (threadCount <= 0)
			threadCount = std::thread::hardware_concurrency() - 2;
		return threadCount;
	}

	static double warmUpSeconds()
	{
		auto milliseconds = helpers::StringHelper::toInt
			(helpers::OptionConverter::getSystemProperty
				(LOG4CXX_STR("LOG4CXX_BENCHMARK_WARM_UP_MILLISECONDS"), LOG4CXX_STR("0")));
		if (milliseconds <= 0)
			milliseconds = 100;
		return milliseconds / 1000;
	}

};

BENCHMARK_DEFINE_F(benchmarker, logDisabledTrace)(benchmark::State& state)
{
	m_logger->setLevel(Level::getDebug());
	for (auto _ : state)
	{
		LOG4CXX_TRACE( m_logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logDisabledTrace)->Name("Logging disabled trace")->MinWarmUpTime(benchmarker::warmUpSeconds());
BENCHMARK_REGISTER_F(benchmarker, logDisabledTrace)->Name("Logging disabled trace")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logDisabledDebug)(benchmark::State& state)
{
	m_logger->setLevel(Level::getInfo());
	for (auto _ : state)
	{
		LOG4CXX_DEBUG(m_logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logDisabledDebug)->Name("Logging disabled debug");

BENCHMARK_DEFINE_F(benchmarker, logStaticString)(benchmark::State& state)
{
	m_logger->setLevel(Level::getInfo());
	for (auto _ : state)
	{
		LOG4CXX_INFO( m_logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logStaticString)->Name("Logging info static string");

BENCHMARK_DEFINE_F(benchmarker, logEnabledDebug)(benchmark::State& state)
{
	m_logger->setLevel( Level::getDebug() );
	for (auto _ : state)
	{
		LOG4CXX_DEBUG( m_logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logEnabledDebug)->Name("Logging enabled debug static string");

BENCHMARK_DEFINE_F(benchmarker, logEnabledTrace)(benchmark::State& state)
{
	m_logger->setLevel( Level::getTrace() );
	for (auto _ : state)
	{
		LOG4CXX_DEBUG( m_logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logEnabledTrace)->Name("Logging enabled trace static string");

#if LOG4CXX_HAS_FMT
BENCHMARK_DEFINE_F(benchmarker, logStaticStringFMT)(benchmark::State& state)
{
	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT(m_logger, "This is a static string to see what happens");
	}
}
BENCHMARK_REGISTER_F(benchmarker, logStaticStringFMT)->Name("Logging static string with FMT");

BENCHMARK_DEFINE_F(benchmarker, logIntValueFMT)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT( m_logger, "Hello m_logger: msg number {}", ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueFMT)->Name("Logging int value with FMT");
BENCHMARK_REGISTER_F(benchmarker, logIntValueFMT)->Name("Logging int value with FMT")->Threads(benchmarker::threadCount());
#endif

BENCHMARK_DEFINE_F(benchmarker, logIntValueStream)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( m_logger, "Hello m_logger: msg number " << ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueStream)->Name("Logging int value with std::ostream");
BENCHMARK_REGISTER_F(benchmarker, logIntValueStream)->Name("Logging int value with std::ostream")->Threads(benchmarker::threadCount());

template <class ...Args>
void logWithConversionPattern(benchmark::State& state, Args&&... args)
{
    auto args_tuple = std::make_tuple(std::move(args)...);
	LogString conversionPattern = std::get<0>(args_tuple);

	PatternLayoutPtr pattern(new PatternLayout);
	pattern->setConversionPattern( conversionPattern );
	auto logger = Logger::getLogger( LOG4CXX_STR("bench_logger") );
	logger->getAppender(LOG4CXX_STR("NullWriterAppender"))->setLayout(pattern);

	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("Hello m_logger: msg number ") << ++x);
	}
}
BENCHMARK_CAPTURE(logWithConversionPattern, NoFormat, LOG4CXX_STR("%m%n"))->Name("NoFormat pattern: %m%n");
BENCHMARK_CAPTURE(logWithConversionPattern, DateOnly, LOG4CXX_STR("[%d] %m%n"))->Name("DateOnly pattern: [%d] %m%n");
BENCHMARK_CAPTURE(logWithConversionPattern, DateClassLevel, LOG4CXX_STR("[%d] [%c] [%p] %m%n"))->Name("DateClassLevel pattern: [%d] [%c] [%p] %m%n");

static void SetAsyncAppender(const benchmark::State& state)
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
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueStream)->Name("Logging int value with std::ostream to AsyncAppender")->Setup(SetAsyncAppender);
BENCHMARK_REGISTER_F(benchmarker, logIntValueStream)->Name("Logging int value with std::ostream to AsyncAppender")->Threads(benchmarker::threadCount());

BENCHMARK_MAIN();

