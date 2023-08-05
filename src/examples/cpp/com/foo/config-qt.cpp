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
	static struct log4cxx_finalizer {
		~log4cxx_finalizer() {
			log4cxx::LogManager::shutdown();
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
	log4cxx::helpers::LogLog::setInternalDebugging(true);
#endif
	log4cxx::qt::Configuration::configureFromFileAndWatch(paths, names);
}

// Retrieve the \c name logger pointer.
auto getLogger(const QString& name) -> LoggerPtr {
	return name.isEmpty()
		? log4cxx::LogManager::getRootLogger()
		: log4cxx::LogManager::getLogger(name);
}

// Retrieve the \c name logger pointer.
auto getLogger(const char* name) -> LoggerPtr {
	return name
		? log4cxx::LogManager::getLogger(std::string(name))
		: log4cxx::LogManager::getRootLogger();
}

} } // namespace com::foo
