/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config-qt.h"
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/logmanager.h>
#include <log4cxx-qt/configuration.h>
#include <log4cxx/helpers/loglog.h>
#include <QCoreApplication>
#include <QVector>
#include <QFileInfo>
#include <QDir>

namespace com { namespace foo {

// Provide the name of the configuration file to Log4cxx.
// Reload the configuration on a QFileSystemWatcher::fileChanged event.
void ConfigureLogging() {
	using namespace log4cxx;
	static struct log4cxx_finalizer {
		~log4cxx_finalizer() {
			LogManager::shutdown();
		}
	} finaliser;
	QFileInfo app{QCoreApplication::applicationFilePath()};
	QString basename{app.baseName()};
	QVector<QString> paths =
		{ QString(".")
		, app.absoluteDir().absolutePath()
		};
	QVector<QString> names =
		{ QString(basename + ".xml")
		, QString(basename + ".properties")
		, QString("MyApp.properties")
		, QString("log4cxx.xml")
		, QString("log4cxx.properties")
		, QString("log4j.xml")
		, QString("log4j.properties")
	};
#if defined(_DEBUG)
	helpers::LogLog::setInternalDebugging(true);
#endif
	auto status       = spi::ConfigurationStatus::NotConfigured;
	auto selectedPath = QString();
	std::tie(status, selectedPath) = qt::Configuration::configureFromFileAndWatch(paths, names);
	if (status == spi::ConfigurationStatus::NotConfigured)
		BasicConfigurator::configure(); // Send events to the console
}

// Retrieve the \c name logger pointer.
auto getLogger(const QString& name) -> LoggerPtr {
	using namespace log4cxx;
	return name.isEmpty()
		? LogManager::getRootLogger()
		: LogManager::getLogger(name.toStdString());
}

// Retrieve the \c name logger pointer.
auto getLogger(const char* name) -> LoggerPtr {
	using namespace log4cxx;
	return name
		? LogManager::getLogger(name)
		: LogManager::getRootLogger();
}

} } // namespace com::foo
