#include <iostream>
#include <pthread.h>
#include <sstream>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/helpers/exception.h>

struct Data
{
    int count;
};

void* LogThread(void* args)
{
    Data* d = (Data*)args;

    // Build Logger Name
    std::ostringstream temp;
    temp << "TestLogger" << d->count;
    std::string loggerName(temp.str());
    std::cout << "getting logger = " << loggerName << std::endl;

    log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger(loggerName));

    while(1)
    {
        logger->debug(loggerName);
        logger->debug("This is a test of the emergency broadcast system.  This is only a test");
        logger->debug("This is a test of the emergency broadcast system. This is only a test");
        logger->debug("This is a test of the emergency broadcast system.  This is only a test");
        logger->debug("This is a test of the emergency broadcast system.  This is only a test");
        logger->debug("This is a test of the emergency broadcast system.  This is only a test");
        logger->debug("This is a test of the emergency broadcast system.  This is only a test");
        logger->debug("This is a test of the emergency broadcast system.  This is only a test");

        usleep(5);
    }

    return 0;
}

int main(void)
{
    log4cxx::LoggerPtr logger(log4cxx::Logger::getRootLogger());
    for(int count = 0; count < 10; count++)
    {
        Data* d = new Data();
        d->count = count;

        pthread_t newThread;
        pthread_create(&newThread, NULL, &LogThread, d);
        sleep(1);
    }

    std::string input;
    std::cout << "Waiting for input to exit" << std::endl;
    std::cin >> input;

    return 0;
}
