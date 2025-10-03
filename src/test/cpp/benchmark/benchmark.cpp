#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/jsonlayout.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/asyncappender.h>
#include <log4cxx/net/smtpappender.h>
#include <log4cxx/net/xmlsocketappender.h>
#include <log4cxx/fileappender.h>
#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
#include <log4cxx/rolling/multiprocessrollingfileappender.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>
#endif
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

#define LOCALHOST_HAS_FLUENT_BIT_RUNNING_ON_PORT_5170 0

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
	BenchmarkFileAppender(const LayoutPtr& layout, bool buffered = true)
	{
		setLayout(layout);
		auto tempDir = helpers::OptionConverter::getSystemProperty(LOG4CXX_STR("TEMP"), LOG4CXX_STR("/tmp"));
		setFile(tempDir + LOG4CXX_STR("/") + LOG4CXX_STR("benchmark.log"));
		setAppend(false);
		setBufferedIO(buffered);
		helpers::Pool p;
		activateOptions(p);
	}
};

class BenchmarkJSONFileAppender : public FileAppender
{
public:
	BenchmarkJSONFileAppender()
	{
		setLayout(std::make_shared<JSONLayout>());
		auto tempDir = helpers::OptionConverter::getSystemProperty(LOG4CXX_STR("TEMP"), LOG4CXX_STR("/tmp"));
		setFile(tempDir + LOG4CXX_STR("/") + LOG4CXX_STR("benchmark.json"));
		setAppend(false);
		setBufferedIO(true);
		helpers::Pool p;
		activateOptions(p);
	}
};

#if LOCALHOST_HAS_FLUENT_BIT_RUNNING_ON_PORT_5170
class BenchmarkFluentbitAppender : public net::XMLSocketAppender
{
public:
	BenchmarkFluentbitAppender()
	{
		setName(LOG4CXX_STR("FluentbitAppender"));
		setLayout(std::make_shared<JSONLayout>());
		setRemoteHost(LOG4CXX_STR("localhost"));
		setPort(5170);
		helpers::Pool p;
		activateOptions(p);
	}
};
#endif

#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
class BenchmarkMultiprocessFileAppender : public rolling::MultiprocessRollingFileAppender
{
public:
	BenchmarkMultiprocessFileAppender(const LayoutPtr& layout)
	{
		setLayout(layout);
		auto tempDir = helpers::OptionConverter::getSystemProperty(LOG4CXX_STR("TEMP"), LOG4CXX_STR("/tmp"));
		auto policy = std::make_shared<rolling::TimeBasedRollingPolicy>();
		policy->setFileNamePattern(tempDir + LOG4CXX_STR("/") + LOG4CXX_STR("multiprocess-%d{yyyy-MM-dd-HH-mm-ss-SSS}.log"));
		setRollingPolicy(policy);
		setFile(tempDir + LOG4CXX_STR("/") + LOG4CXX_STR("multiprocess.log"));
		setBufferedIO(true);
		helpers::Pool p;
		activateOptions(p);
	}
};
#endif

void disableThousandSeparatorsInJSON()
{
	std::setlocale(LC_ALL, "C"); /* Set locale for C functions */
	std::locale::global(std::locale("C")); /* set locale for C++ functions */
}

class benchmarker : public ::benchmark::Fixture
{
public: // Attributes
	LoggerPtr m_appender = getNullWriter();
	LoggerPtr m_asyncLogger = getAsyncLogger();
	LoggerPtr m_fileLogger = getFileLogger();
	LoggerPtr m_JSONLogger = getJSONFileLogger();
#if LOCALHOST_HAS_FLUENT_BIT_RUNNING_ON_PORT_5170
	LoggerPtr m_socketLogger = getFluentbitLogger();
#endif
#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
	LoggerPtr m_multiprocessLogger = getMultiprocessLogger();
#endif

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
			r->setConfigured(true);
			});
	}

	static LoggerPtr getNullWriter(const LogString& pattern = LogString())
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
			helpers::Pool p;
			writer->activateOptions(p);
			result->addAppender(writer);
		}
		return result;
	}

	static LoggerPtr getJSONFileLogger()
	{
		LogString name = LOG4CXX_STR("benchmark.fixture.JSONfile");
		auto r = LogManager::getLoggerRepository();
		LoggerPtr result;
		if (!(result = r->exists(name)))
		{
			result = r->getLogger(name);
			result->setAdditivity(false);
			result->setLevel(Level::getInfo());
			auto writer = std::make_shared<BenchmarkJSONFileAppender>();
			writer->setName(LOG4CXX_STR("JSONFileAppender"));
			writer->setBufferedIO(true);
			helpers::Pool p;
			writer->activateOptions(p);
			result->addAppender(writer);
		}
		return result;
	}

#if LOCALHOST_HAS_FLUENT_BIT_RUNNING_ON_PORT_5170
	static LoggerPtr getFluentbitLogger()
	{
		LogString name = LOG4CXX_STR("benchmark.fixture.Fluentbit");
		auto r = LogManager::getLoggerRepository();
		LoggerPtr result;
		if (!(result = r->exists(name)))
		{
			result = r->getLogger(name);
			result->setAdditivity(false);
			result->setLevel(Level::getInfo());
			auto writer = std::make_shared<BenchmarkFluentbitAppender>();
			helpers::Pool p;
			writer->activateOptions(p);
			result->addAppender(writer);
		}
		return result;
	}
#endif

#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
	static LoggerPtr getMultiprocessLogger()
	{
		LogString name = LOG4CXX_STR("benchmark.fixture.multiprocess");
		auto r = LogManager::getLoggerRepository();
		LoggerPtr result;
		if (!(result = r->exists(name)))
		{
			result = r->getLogger(name);
			result->setAdditivity(false);
			result->setLevel(Level::getInfo());
			auto writer = std::make_shared<BenchmarkMultiprocessFileAppender>(std::make_shared<PatternLayout>(LOG4CXX_STR("%d %m%n")));
			writer->setName(LOG4CXX_STR("MultiprocessFileAppender"));
			helpers::Pool p;
			writer->activateOptions(p);
			result->addAppender(writer);
		}
		return result;
	}
#endif
};

BENCHMARK_DEFINE_F(benchmarker, logDisabledTrace)(benchmark::State& state)
{
	m_appender->setLevel(Level::getDebug());
	for (auto _ : state)
	{
		LOG4CXX_TRACE( m_appender, LOG4CXX_STR("Hello: static string message"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logDisabledTrace)->Name("Testing disabled logging request")->MinWarmUpTime(benchmarker::warmUpSeconds());
BENCHMARK_REGISTER_F(benchmarker, logDisabledTrace)->Name("Testing disabled logging request")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logShortString)(benchmark::State& state)
{
	m_appender->setLevel(Level::getInfo());
	for (auto _ : state)
	{
		LOG4CXX_INFO(m_appender, LOG4CXX_STR("Hello"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logShortString)->Name("Appending 5 char string using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logShortString)->Name("Appending 5 char string using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logLongString)(benchmark::State& state)
{
	m_appender->setLevel(Level::getInfo());
	for (auto _ : state)
	{
		LOG4CXX_INFO( m_appender, LOG4CXX_STR("Hello: this is a long static string message"));
	}
}
BENCHMARK_REGISTER_F(benchmarker, logLongString)->Name("Appending 49 char string using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logLongString)->Name("Appending 49 char string using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntValueMessageBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO( m_appender, "Hello: message number " << ++x);
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
		LOG4CXX_INFO( m_appender, "Hello: message number " << ++x
			<< " pseudo-random float " << std::setprecision(3) << std::fixed << f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatMessageBuffer)->Name("Appending int+float using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatMessageBuffer)->Name("Appending int+float using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntPlus10FloatMessageBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		float f[] =
		{ static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		};
		LOG4CXX_INFO( m_asyncLogger, "Hello: message number " << ++x
			<< " pseudo-random float" << std::setprecision(3) << std::fixed
			<< ' ' << f[0]
			<< ' ' << f[1]
			<< ' ' << f[2]
			<< ' ' << f[3]
			<< ' ' << f[4]
			<< ' ' << f[5]
			<< ' ' << f[6]
			<< ' ' << f[7]
			<< ' ' << f[8]
			<< ' ' << f[9]
			);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntPlus10FloatMessageBuffer)->Name("Appending int+10float using MessageBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntPlus10FloatMessageBuffer)->Name("Appending int+10float using MessageBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

template <class ...Args>
void logWithConversionPattern(benchmark::State& state, Args&&... args)
{
    auto args_tuple = std::make_tuple(std::move(args)...);
	LogString conversionPattern = std::get<0>(args_tuple);
	auto logger = benchmarker::getNullWriter(conversionPattern);
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
		LOG4CXX_INFO_FMT(m_appender, "Hello: this is a long static string message", 0);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logLongStringFMT)->Name("Appending 49 char string using FMT, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logLongStringFMT)->Name("Appending 49 char string using FMT, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntValueFMT)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		LOG4CXX_INFO_FMT(m_appender, "Hello: msg number {}", ++x);
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
		LOG4CXX_INFO_FMT(m_appender, "Hello: msg number {} pseudo-random float {:.3f}", ++x, f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatValueFMT)->Name("Appending int+float using FMT, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntPlusFloatValueFMT)->Name("Appending int+float using FMT, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, logIntPlus10FloatValueFMT)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		float f[] =
		{ static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		};
		LOG4CXX_INFO_FMT(m_appender, "Hello: msg number {} pseudo-random float {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f}"
			, ++x
			, f[0]
			, f[1]
			, f[2]
			, f[3]
			, f[4]
			, f[5]
			, f[6]
			, f[7]
			, f[8]
			, f[9]
			);
	}
}
BENCHMARK_REGISTER_F(benchmarker, logIntPlus10FloatValueFMT)->Name("Appending int+10float using FMT, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, logIntPlus10FloatValueFMT)->Name("Appending int+10float using FMT, pattern: %m%n")->Threads(benchmarker::threadCount());

BENCHMARK_DEFINE_F(benchmarker, asyncIntPlus10FloatValueFmtBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		float f[] =
		{ static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		};
		LOG4CXX_INFO_FMT(m_asyncLogger, "Hello: msg number {} pseudo-random float {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f} {:.3f}"
			, ++x
			, f[0]
			, f[1]
			, f[2]
			, f[3]
			, f[4]
			, f[5]
			, f[6]
			, f[7]
			, f[8]
			, f[9]
			);
	}
}
BENCHMARK_REGISTER_F(benchmarker, asyncIntPlus10FloatValueFmtBuffer)->Name("Async, Sending int+10float using FMT");
BENCHMARK_REGISTER_F(benchmarker, asyncIntPlus10FloatValueFmtBuffer)->Name("Async, Sending int+10float using FMT")->Threads(benchmarker::threadCount());
#endif

BENCHMARK_DEFINE_F(benchmarker, asyncIntPlus10FloatAsyncBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		float f[] =
		{ static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		, static_cast<float>(rand()) / static_cast<float>(RAND_MAX)
		};
		LOG4CXX_INFO_ASYNC(m_asyncLogger, "Hello: message number " << ++x
			<< " pseudo-random float" << std::setprecision(3) << std::fixed
			<< ' ' << f[0]
			<< ' ' << f[1]
			<< ' ' << f[2]
			<< ' ' << f[3]
			<< ' ' << f[4]
			<< ' ' << f[5]
			<< ' ' << f[6]
			<< ' ' << f[7]
			<< ' ' << f[8]
			<< ' ' << f[9]
			);
	}
}
BENCHMARK_REGISTER_F(benchmarker, asyncIntPlus10FloatAsyncBuffer)->Name("Async, Sending int+10float using AsyncBuffer, pattern: %m%n");
BENCHMARK_REGISTER_F(benchmarker, asyncIntPlus10FloatAsyncBuffer)->Name("Async, Sending int+10float using AsyncBuffer, pattern: %m%n")->Threads(benchmarker::threadCount());

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

BENCHMARK_DEFINE_F(benchmarker, fileIntPlusFloatValueMessageBufferJSON)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		auto f = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
		LOG4CXX_INFO( m_JSONLogger, "Hello: message number " << ++x
			<< " pseudo-random float " << std::setprecision(3) << std::fixed << f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, fileIntPlusFloatValueMessageBufferJSON)->Name("Logging int+float using MessageBuffer, JSON");
BENCHMARK_REGISTER_F(benchmarker, fileIntPlusFloatValueMessageBufferJSON)->Name("Logging int+float using MessageBuffer, JSON")->Threads(benchmarker::threadCount());

#if LOCALHOST_HAS_FLUENT_BIT_RUNNING_ON_PORT_5170
BENCHMARK_DEFINE_F(benchmarker, socketIntPlusFloatValueMessageBufferJSON)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		auto f = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
		LOG4CXX_INFO( m_socketLogger, "Hello: message number " << ++x
			<< " pseudo-random float " << std::setprecision(3) << std::fixed << f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, socketIntPlusFloatValueMessageBufferJSON)->Name("Sending int+float using MessageBuffer, JSON");
BENCHMARK_REGISTER_F(benchmarker, socketIntPlusFloatValueMessageBufferJSON)->Name("Sending int+float using MessageBuffer, JSON")->Threads(benchmarker::threadCount());
#endif

#if LOG4CXX_HAS_MULTIPROCESS_ROLLING_FILE_APPENDER
BENCHMARK_DEFINE_F(benchmarker, multiprocessFileIntPlusFloatValueMessageBuffer)(benchmark::State& state)
{
	int x = 0;
	for (auto _ : state)
	{
		auto f = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
		LOG4CXX_INFO( m_multiprocessLogger, "Hello: message number " << ++x
			<< " pseudo-random float " << std::setprecision(3) << std::fixed << f);
	}
}
BENCHMARK_REGISTER_F(benchmarker, multiprocessFileIntPlusFloatValueMessageBuffer)->Name("Multiprocess logging int+float using MessageBuffer, pattern: %d %m%n");
#endif

BENCHMARK_MAIN();

