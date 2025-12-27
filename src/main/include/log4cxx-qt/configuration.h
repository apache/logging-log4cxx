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
#ifndef LOG4CXX_QT_CONFIGURATION_H
#define LOG4CXX_QT_CONFIGURATION_H

#include <log4cxx/spi/configurator.h>
#include <QString>
#include <QVector>
#include <tuple>

namespace LOG4CXX_NS::qt
{

/// Configuration support methods that use the Qt event loop
/// to reload the configuration file when it is modified.
class LOG4CXX_EXPORT Configuration
{
public:
	/**
	 * Select the file to configure Log4cxx and watch the file for changes.  See also DefaultConfigurator::configureFromFile.
	 *
	 * @param directories Each directory is checked for each entry in \c filenames
	 * @param filenames Each file name is checked in each entry in \c directories
	 * @return the selected file path if Log4cxx was successfully configured
	 */
	static std::tuple<spi::ConfigurationStatus, QString> configureFromFileAndWatch
		( const QVector<QString>& directories
		, const QVector<QString>& filenames
		);

	/**
	 * Set up a QFileSystemWatcher that will reconfigure Log4cxx when \c fullPath is modified.
	 */
	static void reconfigureWhenModified(const QString& fullPath);

	/**
	 * Set up a QFileSystemWatcher that will reconfigure Log4cxx when \c fullPath is modified.
	 */
	static void reconfigureWhenModified(const LogString& fullPath);
};

} // namespace LOG4CXX_NS::qt

#endif /* LOG4CXX_QT_CONFIGURATION_H */
