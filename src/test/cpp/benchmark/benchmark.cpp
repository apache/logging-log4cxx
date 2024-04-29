#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/asyncappender.h>
#include <log4cxx/net/smtpappender.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/private/appenderskeleton_priv.h>
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
	NullWriterAppender(const LayoutPtr& layout)
	{
		setLayout(layout);
	}

	void close() override {}

	bool requiresLayout() const override
	{
		return true;
	}

	void append(const spi::LoggingEventPtr& event, helpers::Pool& p) override
	{
		LogString buf;
		m_priv->layout->format(buf, event, p);
	}

	void activateOptions(helpers::Pool& /* pool */) override
	{
	}

	void setOption(const LogString& option, const LogString& value) override
	{
	}
};

class BenchmarkFileAppender : public FileAppender
{
public:
	BenchmarkFileAppender(const LayoutPtr& layout)
	{
		setLayout(layout);
		auto tempDir = helpers::OptionConverter::getSystemProperty(LOG4CXX_STR("TEMP"), LOG4CXX_STR("/tmp"));
		setFile(tempDir + LOG4CXX_STR("/") + LOG4CXX_STR("benchmark.log"));
		setAppend(false);
		setBufferedIO(true);
		helpers::Pool p;
		activateOptions(p);
	}
};

void disableThousandSeparatorsInJSON()
{
	std::setlocale(LC_ALL, "C"); /* Set locale for C functions */
	std::locale::global(std::locale("C")); /* set locale for C++ functions */
}

class benchmarker : public ::benchmark::Fixture
{
public: // Attributes
	LoggerPtr m_logger = getLogger();
	LoggerPtr m_asyncLogger = getAsyncLogger();
	LoggerPtr m_fileLogger = getFileLogger();

public: // Class methods
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

	static void setDefaultAppender()
	{
		auto r = LogManager::getLoggerRepository();
		r->ensureIsConfigured([r]()
			{
			disableThousandSeparatorsInJSON();
			auto writer = std::make_shared<NullWriterAppender>(std::make_shared<PatternLayout>(LOG4CXX_STR("%m%n")));
			writer->setName(LOG4CXX_STR("NullAppender"));
			r->getRootLogger()->addAppender(writer);
			});
	}

	static LoggerPtr getLogger(const LogString& pattern = LogString())
	{
		static struct initializer
		{
			initializer() { setDefaultAppender(); }
			~initializer() { LogManager::shutdown(); }
		} x;
		LogString name = LOG4CXX_STR("benchmark.fixture");
		LoggerPtr result;
		auto r = LogManager::getLoggerRepository();
		if (pattern.empty())
			result = r->getLogger(name);
		else if (!(result = r->exists(name += LOG4CXX_STR(".") + pattern)))
		{
			result = r->getLogger(name);
			result->setAdditivity(false);
			result->setLevel(Level::getInfo());
			auto writer = std::make_shared<NullWriterAppender>(std::make_shared<PatternLayout>(pattern));
			writer->setName(LOG4CXX_STR("NullAppender.") + pattern);
			result->addAppender(writer);
		}
		return result;
	}

	static LoggerPtr getAsyncLogger()
	{
		LogString name = LOG4CXX_STR("benchmark.fixture.async");
		auto r = LogManager::getLoggerRepository();
		LoggerPtr result = r->exists(name);
		if (!result)
		{
			setDefaultAppender();
			auto writer = std::make_shared<net::SMTPAppender>();
			writer->setLayout(std::make_shared<PatternLayout>(LOG4CXX_STR("%m%n")));
			auto asyncAppender = std::make_shared<AsyncAppender>();
			asyncAppender->addAppender(writer);
			asyncAppender->setBlocking(false);
			result = r->getLogger(name);
			result->setAdditivity(false);
			result->setLevel(Level::getInfo());
			result->addAppender(asyncAppender);
		}
		return result;
	}

	static LoggerPtr getFileLogger()
	{
		LogString name = LOG4CXX_STR("benchmark.fixture.file");
		auto r = LogManager::getLoggerRepository();
		LoggerPtr result;
		if (!(result = r->exists(name)))
		{
			result = r->getLogger(name);
			result->setAdditivity(false);
			result->setLevel(Level::getInfo());
			auto writer = std::make_shared<BenchmarkFileAppender>(std::make_shared<PatternLayout>(LOG4CXX_STR("%d %m%n")));
			writer->setName(LOG4CXX_STR("FileAppender"));
			writer->setBufferedIO(true);
			helpers::Pool p;
			writer->activateOptions(p);
			result->addAppender(writer);
		}
		return result;
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
BENCHMARK_REGISTER_F(benchmarker, logShortString)->Name("Appending 5 char string using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logShortString)->Name("Appending 5 char string using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logLongString)(benchmark::State& state)
{
	m_logger->setLevel(Level::getInfo());
	for (auto _ : state)
	{
		LOG4CXX_INFO( m_logger, LOG4CXX_STR("Hello: this is a long static string message"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logLongString)->Name("Appending 49 char string using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logLongString)->Name("Appending 49 char string using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntValueMessageBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( m_logger, "Hello: message number " << ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueMessageBuffer)->Name("Appending int value using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntValueMessageBuffer)->Name("Appending int value using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

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
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatMessageBuffer)->Name("Appending int+float using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatMessageBuffer)->Name("Appending int+float using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

template <class ...Args>
void logWithConversionPattern(benchmark::State& state, Args&&... args)
{
    auto args_tuple = std::make_tuple(std::move(args)...);
	LogString conversionPattern = std::get<0>(args_tuple);
	auto logger = benchmarker::getLogger(conversionPattern);
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("Hello: msg number ") << ++x);
	}
}
BENCHMARK_CAPTURE(logWithConversionPattern, DateMessage, LOG4CXX_STR("[%d] %m%n"))->Name("Appending int value using MessageBuffer, pattern: [%d] %m%n");
BENCHMARK_CAPTURE(logWithConversionPattern, DateClassLevelMessage, LOG4CXX_STR("[%d] [%c] [%p] %m%n"))->Name("Appending int value using MessageBuffer, pattern: [%d] [%c] [%p] %m%n");

#if  LOG4CXX_USING_STD_FORMAT || LOG4CXX_HAS_FMT
BENCHMARK_DEFINE_F(benchmarker, logLongStringFMT)(benchmark::State& state)
{
	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT(m_logger, "Hello: this is a long static string message", 0);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logLongStringFMT)->Name("Appending 49 char string using FMT, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logLongStringFMT)->Name("Appending 49 char string using FMT, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntValueFMT)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT(m_logger, "Hello: msg number {}", ++x);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntValueFMT)->Name("Appending int value using FMT, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntValueFMT)->Name("Appending int value using FMT, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntPlusFloatValueFMT)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		auto f = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
		LOG4CXX_INFO_FMT(m_logger, "Hello: msg number {} pseudo-random float {:.3f}", ++x, f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatValueFMT)->Name("Appending int+float using FMT, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatValueFMT)->Name("Appending int+float using FMT, pattern: %m%n")->Threads(benchmarker::threadCount());
#endif

BENCHMARK_DEFINE_F(benchmarker, asyncIntPlusFloatValueMessageBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		auto f = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
		LOG4CXX_INFO( m_asyncLogger, "Hello: message number " << ++x
			<< " pseudo-random float " << std::setprecision(3) << std::fixed << f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, asyncIntPlusFloatValueMessageBuffer)->Name("Async, Sending int+float using MessageBuffer");
BENCHMARK_REGISTER_F(benchmarker, asyncIntPlusFloatValueMessageBuffer)->Name("Async, Sending int+float using MessageBuffer")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, fileIntPlusFloatValueMessageBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		auto f = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
		LOG4CXX_INFO( m_fileLogger, "Hello: message number " << ++x
			<< " pseudo-random float " << std::setprecision(3) << std::fixed << f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, fileIntPlusFloatValueMessageBuffer)->Name("Logging int+float using MessageBuffer, pattern: %d %m%n");
BENCHMARK_REGISTER_F(benchmarker, fileIntPlusFloatValueMessageBuffer)->Name("Logging int+float using MessageBuffer, pattern: %d %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_MAIN();

