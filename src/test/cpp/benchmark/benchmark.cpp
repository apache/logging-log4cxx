#include <log4cxx/logger.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/asyncappender.h>
#if LOG4CXX_USING_STD_FORMAT
#include <format>
#elif LOG4CXX_HAS_FMT
#include <fmt/format.h>
#endif
#include <benchmark/benchmark.h>
#include <thread>
#include <cstdlib>
#include <iomanip>

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

	NullWriterAppender(const LayoutPtr& layout)
		: AppenderSkeleton(layout)
	{}

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

		auto nullWriter = std::make_shared<NullWriterAppender>(std::make_shared<PatternLayout>(LOG4CXX_STR("%m%n")));
		nullWriter->setName(LOG4CXX_STR("NullWriterAppender"));

		m_logger->addAppender(nullWriter);
	}

	void SetUp(const ::benchmark::State& state)
	{
		std::setlocale( LC_ALL, "C" ); /* Set locale for C functions */
		std::locale::global(std::locale("C")); /* set locale for C++ functions */
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
		LOG4CXX_TRACE( m_logger, LOG4CXX_STR("Hello: static string message"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logDisabledTrace)->Name("Testing disabled logging request")->MinWarmUpTime(benchmarker::warmUpSeconds());
BENCHMARK_REGISTER_F(benchmarker, logDisabledTrace)->Name("Testing disabled logging request")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logShortString)(benchmark::State& state)
{
	m_logger->setLevel(Level::getInfo());
	for (auto _ : state)
	{
		LOG4CXX_INFO(m_logger, LOG4CXX_STR("Hello"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logShortString)->Name("Logging 5 char string using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logShortString)->Name("Logging 5 char string using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logLongString)(benchmark::State& state)
{
	m_logger->setLevel(Level::getInfo());
	for (auto _ : state)
	{
		LOG4CXX_INFO( m_logger, LOG4CXX_STR("Hello: this is a long static string message"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logLongString)->Name("Logging 49 char string using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logLongString)->Name("Logging 49 char string using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntValueMessageBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( m_logger, "Hello: message number " << ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueMessageBuffer)->Name("Logging int value using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntValueMessageBuffer)->Name("Logging int value using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntPlusFloatMessageBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		auto f = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
		LOG4CXX_INFO( m_logger, "Hello: message number " << ++x
			<< " pseudo-random float " << std::setprecision(3) << std::fixed << f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatMessageBuffer)->Name("Logging int+float using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatMessageBuffer)->Name("Logging int+float using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

template <class ...Args>
void logWithConversionPattern(benchmark::State& state, Args&&... args)
{
    auto args_tuple = std::make_tuple(std::move(args)...);
	LogString conversionPattern = std::get<0>(args_tuple);

	auto pattern = std::make_shared<PatternLayout>( conversionPattern );
	auto logger = Logger::getLogger( LOG4CXX_STR("bench_logger") );
	logger->getAppender(LOG4CXX_STR("NullWriterAppender"))->setLayout(pattern);

	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("Hello: msg number ") << ++x);
	}
}
BENCHMARK_CAPTURE(logWithConversionPattern, DateMessage, LOG4CXX_STR("[%d] %m%n"))->Name("Logging int value using MessageBuffer, pattern: [%d] %m%n");
BENCHMARK_CAPTURE(logWithConversionPattern, DateClassLevelMessage, LOG4CXX_STR("[%d] [%c] [%p] %m%n"))->Name("Logging int value using MessageBuffer, pattern: [%d] [%c] [%p] %m%n");

#if  LOG4CXX_USING_STD_FORMAT || LOG4CXX_HAS_FMT
BENCHMARK_DEFINE_F(benchmarker, logLongStringFMT)(benchmark::State& state)
{
	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT(m_logger, "Hello: this is a long static string message", 0);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logLongStringFMT)->Name("Logging 49 char string using FMT, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logLongStringFMT)->Name("Logging 49 char string using FMT, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntValueFMT)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT(m_logger, "Hello: msg number {}", ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueFMT)->Name("Logging int value using FMT, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntValueFMT)->Name("Logging int value using FMT, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntPlusFloatValueFMT)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		auto f = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
		LOG4CXX_INFO_FMT(m_logger, "Hello: msg number {} pseudo-random float {:.3f}", ++x, f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatValueFMT)->Name("Logging int+float using FMT, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatValueFMT)->Name("Logging int+float using FMT, pattern: %m%n")->Threads(benchmarker::threadCount());
#endif

static void SetAsyncAppender(const benchmark::State& state)
{
	auto logger = Logger::getLogger(LOG4CXX_STR("bench_logger"));
	logger->removeAllAppenders();
	logger->setAdditivity(false);
	logger->setLevel(Level::getInfo());

	auto nullWriter = std::make_shared<NullWriterAppender>(std::make_shared<PatternLayout>(LOG4CXX_STR("%m%n")));
	auto asyncAppender = std::make_shared<AsyncAppender>();
	asyncAppender->addAppender(nullWriter);
	asyncAppender->setBufferSize(5);
	logger->addAppender(asyncAppender);
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueMessageBuffer)->Name("Async, int value using MessageBuffer, pattern: %m%n")->Setup(SetAsyncAppender);
BENCHMARK_REGISTER_F(benchmarker, logIntValueMessageBuffer)->Name("Async, int value using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_MAIN();

