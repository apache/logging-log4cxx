/***************************************************************************
               initializationutil.h  -  class InitializationUtil
                             -------------------
    begin                : 2004/01/04
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

void InitializationUtil::initialConfiguration(
	spi::LoggerRepositoryPtr repository, 
	const String& configuratonResourceStr,
	const String& configuratorClassNameStr)
{
	if(configuratonResourceStr.empty()) 
	{
		return;
	}
	URL url = null;
	
	try
	{
	url = new URL(configuratonResourceStr);
	} catch (MalformedURLException ex)
	{
	// so, resource is not a URL:
	// attempt to get the resource from the class path
	url = Loader.getResource(configuratonResourceStr);
	}
	
	// If we have a non-null url, then delegate the rest of the
	// configuration to the OptionConverter.selectAndConfigure
	// method.
	if (url != null) 
	{
	LogLog.info(
	"Using URL [" + url 
	+ "] for automatic log4j configuration of repository named ["+
	repository.getName()+"].");
	OptionConverter.selectAndConfigure(
	url, configuratorClassNameStr, repository);
	} 
	else 
	{
	LogLog.debug(
	"Could not find resources to perform automatic configuration.");
	}    
}
