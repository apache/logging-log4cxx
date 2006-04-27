/*
 * Copyright 2006 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>

#include <log4cxx/simplelayout.h>
#include <log4cxx/consoleappender.h>

#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/thread.h>

#define NUM_THREADS     5
#define LOGGERS_PER_THREAD 50


using namespace log4cxx;
using namespace log4cxx::helpers;

class ThreadTest : public CppUnit::TestFixture
{
   CPPUNIT_TEST_SUITE(ThreadTest);
      CPPUNIT_TEST(testMultiThreadAndJoin);
      CPPUNIT_TEST(testMultiThreadAndShutdown);
   CPPUNIT_TEST_SUITE_END();

public:
   void setUp()
   {
   }

   void tearDown()
   {
      LogManager::shutdown();
   }

   /**
   *   Configure a console appender for tests.
   */
   void configure() {
     LoggerPtr root = Logger::getRootLogger();
     LayoutPtr layout = new SimpleLayout();
     AppenderPtr ca = new ConsoleAppender(layout);
     ca->setName(LOG4CXX_STR("CONSOLE"));
     root->addAppender(ca);
   }

   /**
    *   This test causes interleaved calls to Logger::getLogger() and
    *      Logger::debug from multiple threads
    *      and waits for all threads to complete.
    *
    *  See bug LOGCXX-132
    */
   void testMultiThreadAndJoin() {
      configure();

      Thread threads[NUM_THREADS];
      for(int t = 0; t < NUM_THREADS; t++) {
          threads[t].run(runStatic, 0);
      }

      for(int t = 0; t < NUM_THREADS; t++) {
           threads[t].join();
     }
   }

/**
 *   This test causes interleaved calls to Logger::getLogger() and
 *      Logger::debug from multiple threads but does not await
 *      for the threads to complete resulting in shutting
 *       down the hierarchy while still requesting new loggers.
 *  See bug LOGCXX-132
 */
  void testMultiThreadAndShutdown() {
   configure();

   Thread threads[NUM_THREADS];
   for(int t = 0; t < NUM_THREADS; t++) {
       threads[t].run(runStatic, 0);
   }
}

       static void meth_0() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_0");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_0");
           l->debug(text);
       }

       static void meth_1() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_1");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_1");
           l->debug(text);
       }

       static void meth_2() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_2");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_2");
           l->debug(text);
       }

       static void meth_3() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_3");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_3");
           l->debug(text);
       }

       static void meth_4() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_4");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_4");
           l->debug(text);
       }

       static void meth_5() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_5");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_5");
           l->debug(text);
       }

       static void meth_6() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_6");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_6");
           l->debug(text);
       }

       static void meth_7() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_7");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_7");
           l->debug(text);
       }

       static void meth_8() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_8");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_8");
           l->debug(text);
       }

       static void meth_9() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_9");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_9");
           l->debug(text);
       }

       static void meth_10() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_10");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_10");
           l->debug(text);
       }

       static void meth_11() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_11");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_11");
           l->debug(text);
       }

       static void meth_12() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_12");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_12");
           l->debug(text);
       }

       static void meth_13() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_13");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_13");
           l->debug(text);
       }

       static void meth_14() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_14");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_14");
           l->debug(text);
       }

       static void meth_15() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_15");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_15");
           l->debug(text);
       }

       static void meth_16() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_16");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_16");
           l->debug(text);
       }

       static void meth_17() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_17");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_17");
           l->debug(text);
       }

       static void meth_18() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_18");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_18");
           l->debug(text);
       }

       static void meth_19() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_19");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_19");
           l->debug(text);
       }

       static void meth_20() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_20");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_20");
           l->debug(text);
       }

       static void meth_21() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_21");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_21");
           l->debug(text);
       }

       static void meth_22() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_22");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_22");
           l->debug(text);
       }

       static void meth_23() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_23");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_23");
           l->debug(text);
       }

       static void meth_24() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_24");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_24");
           l->debug(text);
       }

       static void meth_25() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_25");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_25");
           l->debug(text);
       }

       static void meth_26() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_26");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_26");
           l->debug(text);
       }

       static void meth_27() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_27");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_27");
           l->debug(text);
       }

       static void meth_28() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_28");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_28");
           l->debug(text);
       }

       static void meth_29() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_29");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_29");
           l->debug(text);
       }

       static void meth_30() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_30");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_30");
           l->debug(text);
       }

       static void meth_31() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_31");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_31");
           l->debug(text);
       }

       static void meth_32() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_32");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_32");
           l->debug(text);
       }

       static void meth_33() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_33");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_33");
           l->debug(text);
       }

       static void meth_34() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_34");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_34");
           l->debug(text);
       }

       static void meth_35() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_35");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_35");
           l->debug(text);
       }

       static void meth_36() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_36");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_36");
           l->debug(text);
       }

       static void meth_37() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_37");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_37");
           l->debug(text);
       }

       static void meth_38() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_38");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_38");
           l->debug(text);
       }

       static void meth_39() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_39");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_39");
           l->debug(text);
       }

       static void meth_40() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_40");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_40");
           l->debug(text);
       }

       static void meth_41() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_41");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_41");
           l->debug(text);
       }

       static void meth_42() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_42");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_42");
           l->debug(text);
       }

       static void meth_43() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_43");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_43");
           l->debug(text);
       }

       static void meth_44() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_44");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_44");
           l->debug(text);
       }

       static void meth_45() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_45");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_45");
           l->debug(text);
       }

       static void meth_46() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_46");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_46");
           l->debug(text);
       }

       static void meth_47() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_47");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_47");
           l->debug(text);
       }

       static void meth_48() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_48");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_48");
           l->debug(text);
       }

       static void meth_49() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_49");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_49");
           l->debug(text);
       }

       static void meth_50() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_50");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_50");
           l->debug(text);
       }

       static void meth_51() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_51");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_51");
           l->debug(text);
       }

       static void meth_52() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_52");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_52");
           l->debug(text);
       }

       static void meth_53() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_53");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_53");
           l->debug(text);
       }

       static void meth_54() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_54");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_54");
           l->debug(text);
       }

       static void meth_55() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_55");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_55");
           l->debug(text);
       }

       static void meth_56() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_56");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_56");
           l->debug(text);
       }

       static void meth_57() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_57");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_57");
           l->debug(text);
       }

       static void meth_58() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_58");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_58");
           l->debug(text);
       }

       static void meth_59() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_59");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_59");
           l->debug(text);
       }

       static void meth_60() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_60");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_60");
           l->debug(text);
       }

       static void meth_61() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_61");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_61");
           l->debug(text);
       }

       static void meth_62() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_62");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_62");
           l->debug(text);
       }

       static void meth_63() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_63");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_63");
           l->debug(text);
       }

       static void meth_64() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_64");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_64");
           l->debug(text);
       }

       static void meth_65() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_65");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_65");
           l->debug(text);
       }

       static void meth_66() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_66");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_66");
           l->debug(text);
       }

       static void meth_67() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_67");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_67");
           l->debug(text);
       }

       static void meth_68() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_68");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_68");
           l->debug(text);
       }

       static void meth_69() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_69");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_69");
           l->debug(text);
       }

       static void meth_70() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_70");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_70");
           l->debug(text);
       }

       static void meth_71() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_71");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_71");
           l->debug(text);
       }

       static void meth_72() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_72");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_72");
           l->debug(text);
       }

       static void meth_73() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_73");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_73");
           l->debug(text);
       }

       static void meth_74() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_74");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_74");
           l->debug(text);
       }

       static void meth_75() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_75");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_75");
           l->debug(text);
       }

       static void meth_76() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_76");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_76");
           l->debug(text);
       }

       static void meth_77() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_77");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_77");
           l->debug(text);
       }

       static void meth_78() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_78");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_78");
           l->debug(text);
       }

       static void meth_79() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_79");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_79");
           l->debug(text);
       }

       static void meth_80() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_80");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_80");
           l->debug(text);
       }

       static void meth_81() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_81");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_81");
           l->debug(text);
       }

       static void meth_82() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_82");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_82");
           l->debug(text);
       }

       static void meth_83() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_83");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_83");
           l->debug(text);
       }

       static void meth_84() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_84");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_84");
           l->debug(text);
       }

       static void meth_85() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_85");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_85");
           l->debug(text);
       }

       static void meth_86() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_86");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_86");
           l->debug(text);
       }

       static void meth_87() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_87");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_87");
           l->debug(text);
       }

       static void meth_88() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_88");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_88");
           l->debug(text);
       }

       static void meth_89() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_89");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_89");
           l->debug(text);
       }

       static void meth_90() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_90");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_90");
           l->debug(text);
       }

       static void meth_91() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_91");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_91");
           l->debug(text);
       }

       static void meth_92() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_92");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_92");
           l->debug(text);
       }

       static void meth_93() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_93");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_93");
           l->debug(text);
       }

       static void meth_94() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_94");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_94");
           l->debug(text);
       }

       static void meth_95() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_95");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_95");
           l->debug(text);
       }

       static void meth_96() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_96");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_96");
           l->debug(text);
       }

       static void meth_97() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_97");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_97");
           l->debug(text);
       }

       static void meth_98() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_98");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_98");
           l->debug(text);
       }

       static void meth_99() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_99");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_99");
           l->debug(text);
       }

       static void meth_100() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_100");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_100");
           l->debug(text);
       }

       static void meth_101() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_101");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_101");
           l->debug(text);
       }

       static void meth_102() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_102");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_102");
           l->debug(text);
       }

       static void meth_103() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_103");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_103");
           l->debug(text);
       }

       static void meth_104() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_104");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_104");
           l->debug(text);
       }

       static void meth_105() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_105");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_105");
           l->debug(text);
       }

       static void meth_106() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_106");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_106");
           l->debug(text);
       }

       static void meth_107() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_107");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_107");
           l->debug(text);
       }

       static void meth_108() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_108");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_108");
           l->debug(text);
       }

       static void meth_109() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_109");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_109");
           l->debug(text);
       }

       static void meth_110() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_110");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_110");
           l->debug(text);
       }

       static void meth_111() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_111");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_111");
           l->debug(text);
       }

       static void meth_112() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_112");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_112");
           l->debug(text);
       }

       static void meth_113() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_113");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_113");
           l->debug(text);
       }

       static void meth_114() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_114");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_114");
           l->debug(text);
       }

       static void meth_115() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_115");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_115");
           l->debug(text);
       }

       static void meth_116() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_116");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_116");
           l->debug(text);
       }

       static void meth_117() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_117");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_117");
           l->debug(text);
       }

       static void meth_118() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_118");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_118");
           l->debug(text);
       }

       static void meth_119() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_119");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_119");
           l->debug(text);
       }

       static void meth_120() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_120");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_120");
           l->debug(text);
       }

       static void meth_121() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_121");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_121");
           l->debug(text);
       }

       static void meth_122() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_122");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_122");
           l->debug(text);
       }

       static void meth_123() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_123");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_123");
           l->debug(text);
       }

       static void meth_124() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_124");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_124");
           l->debug(text);
       }

       static void meth_125() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_125");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_125");
           l->debug(text);
       }

       static void meth_126() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_126");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_126");
           l->debug(text);
       }

       static void meth_127() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_127");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_127");
           l->debug(text);
       }

       static void meth_128() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_128");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_128");
           l->debug(text);
       }

       static void meth_129() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_129");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_129");
           l->debug(text);
       }

       static void meth_130() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_130");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_130");
           l->debug(text);
       }

       static void meth_131() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_131");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_131");
           l->debug(text);
       }

       static void meth_132() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_132");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_132");
           l->debug(text);
       }

       static void meth_133() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_133");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_133");
           l->debug(text);
       }

       static void meth_134() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_134");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_134");
           l->debug(text);
       }

       static void meth_135() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_135");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_135");
           l->debug(text);
       }

       static void meth_136() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_136");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_136");
           l->debug(text);
       }

       static void meth_137() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_137");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_137");
           l->debug(text);
       }

       static void meth_138() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_138");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_138");
           l->debug(text);
       }

       static void meth_139() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_139");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_139");
           l->debug(text);
       }

       static void meth_140() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_140");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_140");
           l->debug(text);
       }

       static void meth_141() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_141");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_141");
           l->debug(text);
       }

       static void meth_142() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_142");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_142");
           l->debug(text);
       }

       static void meth_143() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_143");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_143");
           l->debug(text);
       }

       static void meth_144() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_144");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_144");
           l->debug(text);
       }

       static void meth_145() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_145");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_145");
           l->debug(text);
       }

       static void meth_146() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_146");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_146");
           l->debug(text);
       }

       static void meth_147() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_147");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_147");
           l->debug(text);
       }

       static void meth_148() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_148");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_148");
           l->debug(text);
       }

       static void meth_149() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_149");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_149");
           l->debug(text);
       }

       static void meth_150() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_150");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_150");
           l->debug(text);
       }

       static void meth_151() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_151");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_151");
           l->debug(text);
       }

       static void meth_152() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_152");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_152");
           l->debug(text);
       }

       static void meth_153() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_153");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_153");
           l->debug(text);
       }

       static void meth_154() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_154");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_154");
           l->debug(text);
       }

       static void meth_155() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_155");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_155");
           l->debug(text);
       }

       static void meth_156() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_156");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_156");
           l->debug(text);
       }

       static void meth_157() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_157");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_157");
           l->debug(text);
       }

       static void meth_158() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_158");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_158");
           l->debug(text);
       }

       static void meth_159() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_159");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_159");
           l->debug(text);
       }

       static void meth_160() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_160");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_160");
           l->debug(text);
       }

       static void meth_161() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_161");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_161");
           l->debug(text);
       }

       static void meth_162() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_162");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_162");
           l->debug(text);
       }

       static void meth_163() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_163");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_163");
           l->debug(text);
       }

       static void meth_164() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_164");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_164");
           l->debug(text);
       }

       static void meth_165() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_165");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_165");
           l->debug(text);
       }

       static void meth_166() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_166");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_166");
           l->debug(text);
       }

       static void meth_167() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_167");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_167");
           l->debug(text);
       }

       static void meth_168() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_168");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_168");
           l->debug(text);
       }

       static void meth_169() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_169");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_169");
           l->debug(text);
       }

       static void meth_170() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_170");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_170");
           l->debug(text);
       }

       static void meth_171() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_171");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_171");
           l->debug(text);
       }

       static void meth_172() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_172");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_172");
           l->debug(text);
       }

       static void meth_173() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_173");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_173");
           l->debug(text);
       }

       static void meth_174() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_174");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_174");
           l->debug(text);
       }

       static void meth_175() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_175");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_175");
           l->debug(text);
       }

       static void meth_176() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_176");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_176");
           l->debug(text);
       }

       static void meth_177() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_177");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_177");
           l->debug(text);
       }

       static void meth_178() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_178");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_178");
           l->debug(text);
       }

       static void meth_179() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_179");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_179");
           l->debug(text);
       }

       static void meth_180() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_180");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_180");
           l->debug(text);
       }

       static void meth_181() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_181");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_181");
           l->debug(text);
       }

       static void meth_182() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_182");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_182");
           l->debug(text);
       }

       static void meth_183() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_183");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_183");
           l->debug(text);
       }

       static void meth_184() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_184");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_184");
           l->debug(text);
       }

       static void meth_185() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_185");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_185");
           l->debug(text);
       }

       static void meth_186() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_186");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_186");
           l->debug(text);
       }

       static void meth_187() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_187");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_187");
           l->debug(text);
       }

       static void meth_188() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_188");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_188");
           l->debug(text);
       }

       static void meth_189() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_189");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_189");
           l->debug(text);
       }

       static void meth_190() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_190");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_190");
           l->debug(text);
       }

       static void meth_191() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_191");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_191");
           l->debug(text);
       }

       static void meth_192() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_192");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_192");
           l->debug(text);
       }

       static void meth_193() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_193");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_193");
           l->debug(text);
       }

       static void meth_194() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_194");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_194");
           l->debug(text);
       }

       static void meth_195() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_195");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_195");
           l->debug(text);
       }

       static void meth_196() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_196");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_196");
           l->debug(text);
       }

       static void meth_197() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_197");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_197");
           l->debug(text);
       }

       static void meth_198() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_198");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_198");
           l->debug(text);
       }

       static void meth_199() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_199");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_199");
           l->debug(text);
       }

       static void meth_200() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_200");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_200");
           l->debug(text);
       }

       static void meth_201() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_201");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_201");
           l->debug(text);
       }

       static void meth_202() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_202");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_202");
           l->debug(text);
       }

       static void meth_203() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_203");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_203");
           l->debug(text);
       }

       static void meth_204() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_204");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_204");
           l->debug(text);
       }

       static void meth_205() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_205");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_205");
           l->debug(text);
       }

       static void meth_206() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_206");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_206");
           l->debug(text);
       }

       static void meth_207() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_207");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_207");
           l->debug(text);
       }

       static void meth_208() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_208");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_208");
           l->debug(text);
       }

       static void meth_209() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_209");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_209");
           l->debug(text);
       }

       static void meth_210() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_210");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_210");
           l->debug(text);
       }

       static void meth_211() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_211");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_211");
           l->debug(text);
       }

       static void meth_212() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_212");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_212");
           l->debug(text);
       }

       static void meth_213() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_213");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_213");
           l->debug(text);
       }

       static void meth_214() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_214");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_214");
           l->debug(text);
       }

       static void meth_215() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_215");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_215");
           l->debug(text);
       }

       static void meth_216() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_216");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_216");
           l->debug(text);
       }

       static void meth_217() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_217");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_217");
           l->debug(text);
       }

       static void meth_218() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_218");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_218");
           l->debug(text);
       }

       static void meth_219() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_219");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_219");
           l->debug(text);
       }

       static void meth_220() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_220");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_220");
           l->debug(text);
       }

       static void meth_221() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_221");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_221");
           l->debug(text);
       }

       static void meth_222() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_222");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_222");
           l->debug(text);
       }

       static void meth_223() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_223");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_223");
           l->debug(text);
       }

       static void meth_224() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_224");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_224");
           l->debug(text);
       }

       static void meth_225() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_225");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_225");
           l->debug(text);
       }

       static void meth_226() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_226");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_226");
           l->debug(text);
       }

       static void meth_227() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_227");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_227");
           l->debug(text);
       }

       static void meth_228() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_228");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_228");
           l->debug(text);
       }

       static void meth_229() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_229");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_229");
           l->debug(text);
       }

       static void meth_230() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_230");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_230");
           l->debug(text);
       }

       static void meth_231() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_231");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_231");
           l->debug(text);
       }

       static void meth_232() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_232");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_232");
           l->debug(text);
       }

       static void meth_233() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_233");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_233");
           l->debug(text);
       }

       static void meth_234() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_234");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_234");
           l->debug(text);
       }

       static void meth_235() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_235");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_235");
           l->debug(text);
       }

       static void meth_236() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_236");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_236");
           l->debug(text);
       }

       static void meth_237() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_237");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_237");
           l->debug(text);
       }

       static void meth_238() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_238");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_238");
           l->debug(text);
       }

       static void meth_239() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_239");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_239");
           l->debug(text);
       }

       static void meth_240() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_240");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_240");
           l->debug(text);
       }

       static void meth_241() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_241");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_241");
           l->debug(text);
       }

       static void meth_242() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_242");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_242");
           l->debug(text);
       }

       static void meth_243() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_243");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_243");
           l->debug(text);
       }

       static void meth_244() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_244");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_244");
           l->debug(text);
       }

       static void meth_245() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_245");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_245");
           l->debug(text);
       }

       static void meth_246() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_246");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_246");
           l->debug(text);
       }

       static void meth_247() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_247");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_247");
           l->debug(text);
       }

       static void meth_248() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_248");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_248");
           l->debug(text);
       }

       static void meth_249() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_249");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_249");
           l->debug(text);
       }

       static void meth_250() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_250");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_250");
           l->debug(text);
       }

       static void meth_251() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_251");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_251");
           l->debug(text);
       }

       static void meth_252() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_252");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_252");
           l->debug(text);
       }

       static void meth_253() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_253");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_253");
           l->debug(text);
       }

       static void meth_254() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_254");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_254");
           l->debug(text);
       }

       static void meth_255() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_255");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_255");
           l->debug(text);
       }

       static void meth_256() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_256");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_256");
           l->debug(text);
       }

       static void meth_257() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_257");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_257");
           l->debug(text);
       }

       static void meth_258() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_258");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_258");
           l->debug(text);
       }

       static void meth_259() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_259");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_259");
           l->debug(text);
       }

       static void meth_260() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_260");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_260");
           l->debug(text);
       }

       static void meth_261() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_261");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_261");
           l->debug(text);
       }

       static void meth_262() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_262");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_262");
           l->debug(text);
       }

       static void meth_263() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_263");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_263");
           l->debug(text);
       }

       static void meth_264() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_264");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_264");
           l->debug(text);
       }

       static void meth_265() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_265");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_265");
           l->debug(text);
       }

       static void meth_266() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_266");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_266");
           l->debug(text);
       }

       static void meth_267() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_267");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_267");
           l->debug(text);
       }

       static void meth_268() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_268");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_268");
           l->debug(text);
       }

       static void meth_269() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_269");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_269");
           l->debug(text);
       }

       static void meth_270() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_270");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_270");
           l->debug(text);
       }

       static void meth_271() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_271");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_271");
           l->debug(text);
       }

       static void meth_272() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_272");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_272");
           l->debug(text);
       }

       static void meth_273() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_273");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_273");
           l->debug(text);
       }

       static void meth_274() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_274");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_274");
           l->debug(text);
       }

       static void meth_275() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_275");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_275");
           l->debug(text);
       }

       static void meth_276() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_276");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_276");
           l->debug(text);
       }

       static void meth_277() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_277");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_277");
           l->debug(text);
       }

       static void meth_278() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_278");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_278");
           l->debug(text);
       }

       static void meth_279() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_279");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_279");
           l->debug(text);
       }

       static void meth_280() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_280");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_280");
           l->debug(text);
       }

       static void meth_281() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_281");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_281");
           l->debug(text);
       }

       static void meth_282() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_282");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_282");
           l->debug(text);
       }

       static void meth_283() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_283");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_283");
           l->debug(text);
       }

       static void meth_284() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_284");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_284");
           l->debug(text);
       }

       static void meth_285() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_285");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_285");
           l->debug(text);
       }

       static void meth_286() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_286");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_286");
           l->debug(text);
       }

       static void meth_287() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_287");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_287");
           l->debug(text);
       }

       static void meth_288() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_288");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_288");
           l->debug(text);
       }

       static void meth_289() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_289");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_289");
           l->debug(text);
       }

       static void meth_290() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_290");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_290");
           l->debug(text);
       }

       static void meth_291() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_291");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_291");
           l->debug(text);
       }

       static void meth_292() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_292");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_292");
           l->debug(text);
       }

       static void meth_293() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_293");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_293");
           l->debug(text);
       }

       static void meth_294() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_294");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_294");
           l->debug(text);
       }

       static void meth_295() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_295");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_295");
           l->debug(text);
       }

       static void meth_296() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_296");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_296");
           l->debug(text);
       }

       static void meth_297() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_297");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_297");
           l->debug(text);
       }

       static void meth_298() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_298");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_298");
           l->debug(text);
       }

       static void meth_299() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_299");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_299");
           l->debug(text);
       }

       static void meth_300() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_300");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_300");
           l->debug(text);
       }

       static void meth_301() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_301");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_301");
           l->debug(text);
       }

       static void meth_302() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_302");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_302");
           l->debug(text);
       }

       static void meth_303() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_303");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_303");
           l->debug(text);
       }

       static void meth_304() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_304");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_304");
           l->debug(text);
       }

       static void meth_305() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_305");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_305");
           l->debug(text);
       }

       static void meth_306() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_306");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_306");
           l->debug(text);
       }

       static void meth_307() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_307");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_307");
           l->debug(text);
       }

       static void meth_308() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_308");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_308");
           l->debug(text);
       }

       static void meth_309() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_309");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_309");
           l->debug(text);
       }

       static void meth_310() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_310");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_310");
           l->debug(text);
       }

       static void meth_311() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_311");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_311");
           l->debug(text);
       }

       static void meth_312() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_312");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_312");
           l->debug(text);
       }

       static void meth_313() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_313");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_313");
           l->debug(text);
       }

       static void meth_314() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_314");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_314");
           l->debug(text);
       }

       static void meth_315() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_315");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_315");
           l->debug(text);
       }

       static void meth_316() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_316");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_316");
           l->debug(text);
       }

       static void meth_317() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_317");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_317");
           l->debug(text);
       }

       static void meth_318() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_318");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_318");
           l->debug(text);
       }

       static void meth_319() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_319");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_319");
           l->debug(text);
       }

       static void meth_320() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_320");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_320");
           l->debug(text);
       }

       static void meth_321() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_321");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_321");
           l->debug(text);
       }

       static void meth_322() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_322");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_322");
           l->debug(text);
       }

       static void meth_323() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_323");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_323");
           l->debug(text);
       }

       static void meth_324() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_324");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_324");
           l->debug(text);
       }

       static void meth_325() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_325");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_325");
           l->debug(text);
       }

       static void meth_326() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_326");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_326");
           l->debug(text);
       }

       static void meth_327() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_327");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_327");
           l->debug(text);
       }

       static void meth_328() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_328");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_328");
           l->debug(text);
       }

       static void meth_329() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_329");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_329");
           l->debug(text);
       }

       static void meth_330() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_330");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_330");
           l->debug(text);
       }

       static void meth_331() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_331");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_331");
           l->debug(text);
       }

       static void meth_332() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_332");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_332");
           l->debug(text);
       }

       static void meth_333() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_333");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_333");
           l->debug(text);
       }

       static void meth_334() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_334");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_334");
           l->debug(text);
       }

       static void meth_335() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_335");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_335");
           l->debug(text);
       }

       static void meth_336() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_336");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_336");
           l->debug(text);
       }

       static void meth_337() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_337");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_337");
           l->debug(text);
       }

       static void meth_338() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_338");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_338");
           l->debug(text);
       }

       static void meth_339() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_339");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_339");
           l->debug(text);
       }

       static void meth_340() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_340");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_340");
           l->debug(text);
       }

       static void meth_341() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_341");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_341");
           l->debug(text);
       }

       static void meth_342() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_342");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_342");
           l->debug(text);
       }

       static void meth_343() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_343");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_343");
           l->debug(text);
       }

       static void meth_344() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_344");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_344");
           l->debug(text);
       }

       static void meth_345() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_345");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_345");
           l->debug(text);
       }

       static void meth_346() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_346");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_346");
           l->debug(text);
       }

       static void meth_347() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_347");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_347");
           l->debug(text);
       }

       static void meth_348() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_348");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_348");
           l->debug(text);
       }

       static void meth_349() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_349");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_349");
           l->debug(text);
       }

       static void meth_350() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_350");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_350");
           l->debug(text);
       }

       static void meth_351() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_351");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_351");
           l->debug(text);
       }

       static void meth_352() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_352");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_352");
           l->debug(text);
       }

       static void meth_353() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_353");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_353");
           l->debug(text);
       }

       static void meth_354() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_354");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_354");
           l->debug(text);
       }

       static void meth_355() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_355");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_355");
           l->debug(text);
       }

       static void meth_356() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_356");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_356");
           l->debug(text);
       }

       static void meth_357() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_357");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_357");
           l->debug(text);
       }

       static void meth_358() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_358");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_358");
           l->debug(text);
       }

       static void meth_359() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_359");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_359");
           l->debug(text);
       }

       static void meth_360() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_360");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_360");
           l->debug(text);
       }

       static void meth_361() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_361");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_361");
           l->debug(text);
       }

       static void meth_362() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_362");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_362");
           l->debug(text);
       }

       static void meth_363() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_363");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_363");
           l->debug(text);
       }

       static void meth_364() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_364");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_364");
           l->debug(text);
       }

       static void meth_365() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_365");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_365");
           l->debug(text);
       }

       static void meth_366() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_366");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_366");
           l->debug(text);
       }

       static void meth_367() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_367");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_367");
           l->debug(text);
       }

       static void meth_368() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_368");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_368");
           l->debug(text);
       }

       static void meth_369() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_369");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_369");
           l->debug(text);
       }

       static void meth_370() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_370");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_370");
           l->debug(text);
       }

       static void meth_371() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_371");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_371");
           l->debug(text);
       }

       static void meth_372() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_372");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_372");
           l->debug(text);
       }

       static void meth_373() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_373");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_373");
           l->debug(text);
       }

       static void meth_374() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_374");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_374");
           l->debug(text);
       }

       static void meth_375() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_375");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_375");
           l->debug(text);
       }

       static void meth_376() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_376");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_376");
           l->debug(text);
       }

       static void meth_377() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_377");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_377");
           l->debug(text);
       }

       static void meth_378() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_378");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_378");
           l->debug(text);
       }

       static void meth_379() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_379");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_379");
           l->debug(text);
       }

       static void meth_380() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_380");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_380");
           l->debug(text);
       }

       static void meth_381() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_381");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_381");
           l->debug(text);
       }

       static void meth_382() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_382");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_382");
           l->debug(text);
       }

       static void meth_383() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_383");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_383");
           l->debug(text);
       }

       static void meth_384() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_384");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_384");
           l->debug(text);
       }

       static void meth_385() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_385");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_385");
           l->debug(text);
       }

       static void meth_386() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_386");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_386");
           l->debug(text);
       }

       static void meth_387() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_387");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_387");
           l->debug(text);
       }

       static void meth_388() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_388");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_388");
           l->debug(text);
       }

       static void meth_389() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_389");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_389");
           l->debug(text);
       }

       static void meth_390() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_390");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_390");
           l->debug(text);
       }

       static void meth_391() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_391");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_391");
           l->debug(text);
       }

       static void meth_392() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_392");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_392");
           l->debug(text);
       }

       static void meth_393() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_393");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_393");
           l->debug(text);
       }

       static void meth_394() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_394");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_394");
           l->debug(text);
       }

       static void meth_395() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_395");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_395");
           l->debug(text);
       }

       static void meth_396() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_396");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_396");
           l->debug(text);
       }

       static void meth_397() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_397");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_397");
           l->debug(text);
       }

       static void meth_398() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_398");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_398");
           l->debug(text);
       }

       static void meth_399() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_399");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_399");
           l->debug(text);
       }

       static void meth_400() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_400");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_400");
           l->debug(text);
       }

       static void meth_401() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_401");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_401");
           l->debug(text);
       }

       static void meth_402() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_402");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_402");
           l->debug(text);
       }

       static void meth_403() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_403");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_403");
           l->debug(text);
       }

       static void meth_404() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_404");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_404");
           l->debug(text);
       }

       static void meth_405() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_405");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_405");
           l->debug(text);
       }

       static void meth_406() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_406");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_406");
           l->debug(text);
       }

       static void meth_407() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_407");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_407");
           l->debug(text);
       }

       static void meth_408() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_408");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_408");
           l->debug(text);
       }

       static void meth_409() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_409");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_409");
           l->debug(text);
       }

       static void meth_410() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_410");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_410");
           l->debug(text);
       }

       static void meth_411() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_411");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_411");
           l->debug(text);
       }

       static void meth_412() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_412");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_412");
           l->debug(text);
       }

       static void meth_413() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_413");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_413");
           l->debug(text);
       }

       static void meth_414() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_414");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_414");
           l->debug(text);
       }

       static void meth_415() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_415");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_415");
           l->debug(text);
       }

       static void meth_416() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_416");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_416");
           l->debug(text);
       }

       static void meth_417() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_417");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_417");
           l->debug(text);
       }

       static void meth_418() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_418");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_418");
           l->debug(text);
       }

       static void meth_419() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_419");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_419");
           l->debug(text);
       }

       static void meth_420() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_420");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_420");
           l->debug(text);
       }

       static void meth_421() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_421");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_421");
           l->debug(text);
       }

       static void meth_422() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_422");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_422");
           l->debug(text);
       }

       static void meth_423() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_423");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_423");
           l->debug(text);
       }

       static void meth_424() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_424");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_424");
           l->debug(text);
       }

       static void meth_425() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_425");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_425");
           l->debug(text);
       }

       static void meth_426() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_426");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_426");
           l->debug(text);
       }

       static void meth_427() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_427");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_427");
           l->debug(text);
       }

       static void meth_428() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_428");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_428");
           l->debug(text);
       }

       static void meth_429() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_429");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_429");
           l->debug(text);
       }

       static void meth_430() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_430");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_430");
           l->debug(text);
       }

       static void meth_431() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_431");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_431");
           l->debug(text);
       }

       static void meth_432() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_432");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_432");
           l->debug(text);
       }

       static void meth_433() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_433");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_433");
           l->debug(text);
       }

       static void meth_434() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_434");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_434");
           l->debug(text);
       }

       static void meth_435() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_435");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_435");
           l->debug(text);
       }

       static void meth_436() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_436");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_436");
           l->debug(text);
       }

       static void meth_437() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_437");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_437");
           l->debug(text);
       }

       static void meth_438() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_438");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_438");
           l->debug(text);
       }

       static void meth_439() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_439");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_439");
           l->debug(text);
       }

       static void meth_440() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_440");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_440");
           l->debug(text);
       }

       static void meth_441() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_441");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_441");
           l->debug(text);
       }

       static void meth_442() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_442");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_442");
           l->debug(text);
       }

       static void meth_443() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_443");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_443");
           l->debug(text);
       }

       static void meth_444() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_444");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_444");
           l->debug(text);
       }

       static void meth_445() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_445");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_445");
           l->debug(text);
       }

       static void meth_446() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_446");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_446");
           l->debug(text);
       }

       static void meth_447() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_447");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_447");
           l->debug(text);
       }

       static void meth_448() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_448");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_448");
           l->debug(text);
       }

       static void meth_449() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_449");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_449");
           l->debug(text);
       }

       static void meth_450() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_450");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_450");
           l->debug(text);
       }

       static void meth_451() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_451");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_451");
           l->debug(text);
       }

       static void meth_452() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_452");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_452");
           l->debug(text);
       }

       static void meth_453() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_453");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_453");
           l->debug(text);
       }

       static void meth_454() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_454");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_454");
           l->debug(text);
       }

       static void meth_455() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_455");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_455");
           l->debug(text);
       }

       static void meth_456() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_456");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_456");
           l->debug(text);
       }

       static void meth_457() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_457");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_457");
           l->debug(text);
       }

       static void meth_458() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_458");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_458");
           l->debug(text);
       }

       static void meth_459() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_459");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_459");
           l->debug(text);
       }

       static void meth_460() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_460");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_460");
           l->debug(text);
       }

       static void meth_461() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_461");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_461");
           l->debug(text);
       }

       static void meth_462() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_462");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_462");
           l->debug(text);
       }

       static void meth_463() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_463");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_463");
           l->debug(text);
       }

       static void meth_464() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_464");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_464");
           l->debug(text);
       }

       static void meth_465() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_465");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_465");
           l->debug(text);
       }

       static void meth_466() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_466");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_466");
           l->debug(text);
       }

       static void meth_467() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_467");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_467");
           l->debug(text);
       }

       static void meth_468() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_468");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_468");
           l->debug(text);
       }

       static void meth_469() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_469");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_469");
           l->debug(text);
       }

       static void meth_470() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_470");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_470");
           l->debug(text);
       }

       static void meth_471() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_471");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_471");
           l->debug(text);
       }

       static void meth_472() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_472");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_472");
           l->debug(text);
       }

       static void meth_473() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_473");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_473");
           l->debug(text);
       }

       static void meth_474() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_474");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_474");
           l->debug(text);
       }

       static void meth_475() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_475");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_475");
           l->debug(text);
       }

       static void meth_476() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_476");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_476");
           l->debug(text);
       }

       static void meth_477() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_477");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_477");
           l->debug(text);
       }

       static void meth_478() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_478");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_478");
           l->debug(text);
       }

       static void meth_479() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_479");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_479");
           l->debug(text);
       }

       static void meth_480() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_480");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_480");
           l->debug(text);
       }

       static void meth_481() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_481");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_481");
           l->debug(text);
       }

       static void meth_482() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_482");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_482");
           l->debug(text);
       }

       static void meth_483() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_483");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_483");
           l->debug(text);
       }

       static void meth_484() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_484");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_484");
           l->debug(text);
       }

       static void meth_485() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_485");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_485");
           l->debug(text);
       }

       static void meth_486() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_486");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_486");
           l->debug(text);
       }

       static void meth_487() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_487");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_487");
           l->debug(text);
       }

       static void meth_488() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_488");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_488");
           l->debug(text);
       }

       static void meth_489() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_489");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_489");
           l->debug(text);
       }

       static void meth_490() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_490");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_490");
           l->debug(text);
       }

       static void meth_491() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_491");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_491");
           l->debug(text);
       }

       static void meth_492() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_492");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_492");
           l->debug(text);
       }

       static void meth_493() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_493");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_493");
           l->debug(text);
       }

       static void meth_494() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_494");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_494");
           l->debug(text);
       }

       static void meth_495() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_495");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_495");
           l->debug(text);
       }

       static void meth_496() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_496");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_496");
           l->debug(text);
       }

       static void meth_497() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_497");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_497");
           l->debug(text);
       }

       static void meth_498() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_498");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_498");
           l->debug(text);
       }

       static void meth_499() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_499");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_499");
           l->debug(text);
       }

       static void meth_500() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_500");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_500");
           l->debug(text);
       }

       static void meth_501() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_501");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_501");
           l->debug(text);
       }

       static void meth_502() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_502");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_502");
           l->debug(text);
       }

       static void meth_503() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_503");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_503");
           l->debug(text);
       }

       static void meth_504() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_504");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_504");
           l->debug(text);
       }

       static void meth_505() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_505");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_505");
           l->debug(text);
       }

       static void meth_506() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_506");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_506");
           l->debug(text);
       }

       static void meth_507() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_507");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_507");
           l->debug(text);
       }

       static void meth_508() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_508");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_508");
           l->debug(text);
       }

       static void meth_509() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_509");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_509");
           l->debug(text);
       }

       static void meth_510() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_510");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_510");
           l->debug(text);
       }

       static void meth_511() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_511");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_511");
           l->debug(text);
       }

       static void meth_512() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_512");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_512");
           l->debug(text);
       }

       static void meth_513() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_513");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_513");
           l->debug(text);
       }

       static void meth_514() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_514");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_514");
           l->debug(text);
       }

       static void meth_515() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_515");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_515");
           l->debug(text);
       }

       static void meth_516() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_516");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_516");
           l->debug(text);
       }

       static void meth_517() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_517");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_517");
           l->debug(text);
       }

       static void meth_518() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_518");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_518");
           l->debug(text);
       }

       static void meth_519() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_519");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_519");
           l->debug(text);
       }

       static void meth_520() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_520");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_520");
           l->debug(text);
       }

       static void meth_521() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_521");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_521");
           l->debug(text);
       }

       static void meth_522() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_522");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_522");
           l->debug(text);
       }

       static void meth_523() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_523");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_523");
           l->debug(text);
       }

       static void meth_524() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_524");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_524");
           l->debug(text);
       }

       static void meth_525() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_525");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_525");
           l->debug(text);
       }

       static void meth_526() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_526");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_526");
           l->debug(text);
       }

       static void meth_527() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_527");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_527");
           l->debug(text);
       }

       static void meth_528() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_528");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_528");
           l->debug(text);
       }

       static void meth_529() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_529");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_529");
           l->debug(text);
       }

       static void meth_530() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_530");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_530");
           l->debug(text);
       }

       static void meth_531() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_531");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_531");
           l->debug(text);
       }

       static void meth_532() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_532");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_532");
           l->debug(text);
       }

       static void meth_533() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_533");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_533");
           l->debug(text);
       }

       static void meth_534() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_534");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_534");
           l->debug(text);
       }

       static void meth_535() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_535");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_535");
           l->debug(text);
       }

       static void meth_536() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_536");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_536");
           l->debug(text);
       }

       static void meth_537() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_537");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_537");
           l->debug(text);
       }

       static void meth_538() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_538");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_538");
           l->debug(text);
       }

       static void meth_539() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_539");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_539");
           l->debug(text);
       }

       static void meth_540() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_540");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_540");
           l->debug(text);
       }

       static void meth_541() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_541");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_541");
           l->debug(text);
       }

       static void meth_542() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_542");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_542");
           l->debug(text);
       }

       static void meth_543() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_543");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_543");
           l->debug(text);
       }

       static void meth_544() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_544");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_544");
           l->debug(text);
       }

       static void meth_545() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_545");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_545");
           l->debug(text);
       }

       static void meth_546() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_546");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_546");
           l->debug(text);
       }

       static void meth_547() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_547");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_547");
           l->debug(text);
       }

       static void meth_548() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_548");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_548");
           l->debug(text);
       }

       static void meth_549() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_549");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_549");
           l->debug(text);
       }

       static void meth_550() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_550");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_550");
           l->debug(text);
       }

       static void meth_551() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_551");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_551");
           l->debug(text);
       }

       static void meth_552() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_552");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_552");
           l->debug(text);
       }

       static void meth_553() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_553");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_553");
           l->debug(text);
       }

       static void meth_554() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_554");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_554");
           l->debug(text);
       }

       static void meth_555() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_555");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_555");
           l->debug(text);
       }

       static void meth_556() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_556");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_556");
           l->debug(text);
       }

       static void meth_557() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_557");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_557");
           l->debug(text);
       }

       static void meth_558() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_558");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_558");
           l->debug(text);
       }

       static void meth_559() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_559");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_559");
           l->debug(text);
       }

       static void meth_560() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_560");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_560");
           l->debug(text);
       }

       static void meth_561() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_561");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_561");
           l->debug(text);
       }

       static void meth_562() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_562");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_562");
           l->debug(text);
       }

       static void meth_563() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_563");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_563");
           l->debug(text);
       }

       static void meth_564() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_564");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_564");
           l->debug(text);
       }

       static void meth_565() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_565");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_565");
           l->debug(text);
       }

       static void meth_566() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_566");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_566");
           l->debug(text);
       }

       static void meth_567() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_567");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_567");
           l->debug(text);
       }

       static void meth_568() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_568");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_568");
           l->debug(text);
       }

       static void meth_569() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_569");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_569");
           l->debug(text);
       }

       static void meth_570() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_570");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_570");
           l->debug(text);
       }

       static void meth_571() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_571");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_571");
           l->debug(text);
       }

       static void meth_572() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_572");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_572");
           l->debug(text);
       }

       static void meth_573() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_573");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_573");
           l->debug(text);
       }

       static void meth_574() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_574");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_574");
           l->debug(text);
       }

       static void meth_575() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_575");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_575");
           l->debug(text);
       }

       static void meth_576() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_576");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_576");
           l->debug(text);
       }

       static void meth_577() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_577");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_577");
           l->debug(text);
       }

       static void meth_578() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_578");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_578");
           l->debug(text);
       }

       static void meth_579() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_579");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_579");
           l->debug(text);
       }

       static void meth_580() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_580");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_580");
           l->debug(text);
       }

       static void meth_581() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_581");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_581");
           l->debug(text);
       }

       static void meth_582() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_582");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_582");
           l->debug(text);
       }

       static void meth_583() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_583");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_583");
           l->debug(text);
       }

       static void meth_584() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_584");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_584");
           l->debug(text);
       }

       static void meth_585() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_585");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_585");
           l->debug(text);
       }

       static void meth_586() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_586");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_586");
           l->debug(text);
       }

       static void meth_587() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_587");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_587");
           l->debug(text);
       }

       static void meth_588() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_588");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_588");
           l->debug(text);
       }

       static void meth_589() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_589");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_589");
           l->debug(text);
       }

       static void meth_590() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_590");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_590");
           l->debug(text);
       }

       static void meth_591() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_591");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_591");
           l->debug(text);
       }

       static void meth_592() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_592");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_592");
           l->debug(text);
       }

       static void meth_593() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_593");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_593");
           l->debug(text);
       }

       static void meth_594() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_594");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_594");
           l->debug(text);
       }

       static void meth_595() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_595");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_595");
           l->debug(text);
       }

       static void meth_596() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_596");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_596");
           l->debug(text);
       }

       static void meth_597() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_597");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_597");
           l->debug(text);
       }

       static void meth_598() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_598");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_598");
           l->debug(text);
       }

       static void meth_599() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_599");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_599");
           l->debug(text);
       }

       static void meth_600() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_600");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_600");
           l->debug(text);
       }

       static void meth_601() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_601");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_601");
           l->debug(text);
       }

       static void meth_602() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_602");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_602");
           l->debug(text);
       }

       static void meth_603() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_603");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_603");
           l->debug(text);
       }

       static void meth_604() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_604");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_604");
           l->debug(text);
       }

       static void meth_605() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_605");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_605");
           l->debug(text);
       }

       static void meth_606() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_606");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_606");
           l->debug(text);
       }

       static void meth_607() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_607");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_607");
           l->debug(text);
       }

       static void meth_608() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_608");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_608");
           l->debug(text);
       }

       static void meth_609() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_609");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_609");
           l->debug(text);
       }

       static void meth_610() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_610");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_610");
           l->debug(text);
       }

       static void meth_611() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_611");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_611");
           l->debug(text);
       }

       static void meth_612() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_612");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_612");
           l->debug(text);
       }

       static void meth_613() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_613");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_613");
           l->debug(text);
       }

       static void meth_614() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_614");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_614");
           l->debug(text);
       }

       static void meth_615() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_615");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_615");
           l->debug(text);
       }

       static void meth_616() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_616");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_616");
           l->debug(text);
       }

       static void meth_617() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_617");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_617");
           l->debug(text);
       }

       static void meth_618() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_618");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_618");
           l->debug(text);
       }

       static void meth_619() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_619");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_619");
           l->debug(text);
       }

       static void meth_620() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_620");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_620");
           l->debug(text);
       }

       static void meth_621() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_621");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_621");
           l->debug(text);
       }

       static void meth_622() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_622");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_622");
           l->debug(text);
       }

       static void meth_623() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_623");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_623");
           l->debug(text);
       }

       static void meth_624() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_624");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_624");
           l->debug(text);
       }

       static void meth_625() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_625");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_625");
           l->debug(text);
       }

       static void meth_626() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_626");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_626");
           l->debug(text);
       }

       static void meth_627() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_627");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_627");
           l->debug(text);
       }

       static void meth_628() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_628");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_628");
           l->debug(text);
       }

       static void meth_629() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_629");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_629");
           l->debug(text);
       }

       static void meth_630() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_630");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_630");
           l->debug(text);
       }

       static void meth_631() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_631");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_631");
           l->debug(text);
       }

       static void meth_632() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_632");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_632");
           l->debug(text);
       }

       static void meth_633() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_633");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_633");
           l->debug(text);
       }

       static void meth_634() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_634");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_634");
           l->debug(text);
       }

       static void meth_635() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_635");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_635");
           l->debug(text);
       }

       static void meth_636() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_636");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_636");
           l->debug(text);
       }

       static void meth_637() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_637");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_637");
           l->debug(text);
       }

       static void meth_638() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_638");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_638");
           l->debug(text);
       }

       static void meth_639() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_639");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_639");
           l->debug(text);
       }

       static void meth_640() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_640");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_640");
           l->debug(text);
       }

       static void meth_641() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_641");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_641");
           l->debug(text);
       }

       static void meth_642() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_642");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_642");
           l->debug(text);
       }

       static void meth_643() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_643");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_643");
           l->debug(text);
       }

       static void meth_644() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_644");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_644");
           l->debug(text);
       }

       static void meth_645() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_645");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_645");
           l->debug(text);
       }

       static void meth_646() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_646");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_646");
           l->debug(text);
       }

       static void meth_647() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_647");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_647");
           l->debug(text);
       }

       static void meth_648() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_648");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_648");
           l->debug(text);
       }

       static void meth_649() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_649");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_649");
           l->debug(text);
       }

       static void meth_650() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_650");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_650");
           l->debug(text);
       }

       static void meth_651() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_651");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_651");
           l->debug(text);
       }

       static void meth_652() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_652");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_652");
           l->debug(text);
       }

       static void meth_653() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_653");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_653");
           l->debug(text);
       }

       static void meth_654() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_654");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_654");
           l->debug(text);
       }

       static void meth_655() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_655");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_655");
           l->debug(text);
       }

       static void meth_656() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_656");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_656");
           l->debug(text);
       }

       static void meth_657() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_657");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_657");
           l->debug(text);
       }

       static void meth_658() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_658");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_658");
           l->debug(text);
       }

       static void meth_659() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_659");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_659");
           l->debug(text);
       }

       static void meth_660() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_660");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_660");
           l->debug(text);
       }

       static void meth_661() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_661");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_661");
           l->debug(text);
       }

       static void meth_662() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_662");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_662");
           l->debug(text);
       }

       static void meth_663() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_663");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_663");
           l->debug(text);
       }

       static void meth_664() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_664");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_664");
           l->debug(text);
       }

       static void meth_665() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_665");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_665");
           l->debug(text);
       }

       static void meth_666() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_666");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_666");
           l->debug(text);
       }

       static void meth_667() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_667");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_667");
           l->debug(text);
       }

       static void meth_668() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_668");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_668");
           l->debug(text);
       }

       static void meth_669() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_669");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_669");
           l->debug(text);
       }

       static void meth_670() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_670");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_670");
           l->debug(text);
       }

       static void meth_671() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_671");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_671");
           l->debug(text);
       }

       static void meth_672() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_672");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_672");
           l->debug(text);
       }

       static void meth_673() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_673");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_673");
           l->debug(text);
       }

       static void meth_674() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_674");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_674");
           l->debug(text);
       }

       static void meth_675() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_675");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_675");
           l->debug(text);
       }

       static void meth_676() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_676");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_676");
           l->debug(text);
       }

       static void meth_677() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_677");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_677");
           l->debug(text);
       }

       static void meth_678() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_678");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_678");
           l->debug(text);
       }

       static void meth_679() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_679");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_679");
           l->debug(text);
       }

       static void meth_680() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_680");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_680");
           l->debug(text);
       }

       static void meth_681() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_681");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_681");
           l->debug(text);
       }

       static void meth_682() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_682");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_682");
           l->debug(text);
       }

       static void meth_683() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_683");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_683");
           l->debug(text);
       }

       static void meth_684() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_684");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_684");
           l->debug(text);
       }

       static void meth_685() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_685");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_685");
           l->debug(text);
       }

       static void meth_686() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_686");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_686");
           l->debug(text);
       }

       static void meth_687() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_687");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_687");
           l->debug(text);
       }

       static void meth_688() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_688");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_688");
           l->debug(text);
       }

       static void meth_689() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_689");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_689");
           l->debug(text);
       }

       static void meth_690() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_690");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_690");
           l->debug(text);
       }

       static void meth_691() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_691");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_691");
           l->debug(text);
       }

       static void meth_692() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_692");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_692");
           l->debug(text);
       }

       static void meth_693() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_693");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_693");
           l->debug(text);
       }

       static void meth_694() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_694");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_694");
           l->debug(text);
       }

       static void meth_695() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_695");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_695");
           l->debug(text);
       }

       static void meth_696() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_696");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_696");
           l->debug(text);
       }

       static void meth_697() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_697");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_697");
           l->debug(text);
       }

       static void meth_698() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_698");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_698");
           l->debug(text);
       }

       static void meth_699() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_699");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_699");
           l->debug(text);
       }

       static void meth_700() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_700");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_700");
           l->debug(text);
       }

       static void meth_701() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_701");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_701");
           l->debug(text);
       }

       static void meth_702() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_702");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_702");
           l->debug(text);
       }

       static void meth_703() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_703");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_703");
           l->debug(text);
       }

       static void meth_704() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_704");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_704");
           l->debug(text);
       }

       static void meth_705() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_705");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_705");
           l->debug(text);
       }

       static void meth_706() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_706");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_706");
           l->debug(text);
       }

       static void meth_707() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_707");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_707");
           l->debug(text);
       }

       static void meth_708() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_708");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_708");
           l->debug(text);
       }

       static void meth_709() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_709");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_709");
           l->debug(text);
       }

       static void meth_710() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_710");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_710");
           l->debug(text);
       }

       static void meth_711() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_711");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_711");
           l->debug(text);
       }

       static void meth_712() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_712");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_712");
           l->debug(text);
       }

       static void meth_713() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_713");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_713");
           l->debug(text);
       }

       static void meth_714() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_714");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_714");
           l->debug(text);
       }

       static void meth_715() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_715");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_715");
           l->debug(text);
       }

       static void meth_716() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_716");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_716");
           l->debug(text);
       }

       static void meth_717() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_717");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_717");
           l->debug(text);
       }

       static void meth_718() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_718");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_718");
           l->debug(text);
       }

       static void meth_719() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_719");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_719");
           l->debug(text);
       }

       static void meth_720() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_720");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_720");
           l->debug(text);
       }

       static void meth_721() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_721");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_721");
           l->debug(text);
       }

       static void meth_722() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_722");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_722");
           l->debug(text);
       }

       static void meth_723() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_723");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_723");
           l->debug(text);
       }

       static void meth_724() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_724");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_724");
           l->debug(text);
       }

       static void meth_725() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_725");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_725");
           l->debug(text);
       }

       static void meth_726() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_726");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_726");
           l->debug(text);
       }

       static void meth_727() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_727");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_727");
           l->debug(text);
       }

       static void meth_728() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_728");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_728");
           l->debug(text);
       }

       static void meth_729() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_729");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_729");
           l->debug(text);
       }

       static void meth_730() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_730");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_730");
           l->debug(text);
       }

       static void meth_731() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_731");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_731");
           l->debug(text);
       }

       static void meth_732() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_732");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_732");
           l->debug(text);
       }

       static void meth_733() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_733");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_733");
           l->debug(text);
       }

       static void meth_734() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_734");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_734");
           l->debug(text);
       }

       static void meth_735() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_735");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_735");
           l->debug(text);
       }

       static void meth_736() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_736");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_736");
           l->debug(text);
       }

       static void meth_737() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_737");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_737");
           l->debug(text);
       }

       static void meth_738() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_738");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_738");
           l->debug(text);
       }

       static void meth_739() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_739");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_739");
           l->debug(text);
       }

       static void meth_740() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_740");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_740");
           l->debug(text);
       }

       static void meth_741() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_741");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_741");
           l->debug(text);
       }

       static void meth_742() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_742");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_742");
           l->debug(text);
       }

       static void meth_743() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_743");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_743");
           l->debug(text);
       }

       static void meth_744() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_744");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_744");
           l->debug(text);
       }

       static void meth_745() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_745");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_745");
           l->debug(text);
       }

       static void meth_746() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_746");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_746");
           l->debug(text);
       }

       static void meth_747() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_747");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_747");
           l->debug(text);
       }

       static void meth_748() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_748");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_748");
           l->debug(text);
       }

       static void meth_749() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_749");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_749");
           l->debug(text);
       }

       static void meth_750() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_750");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_750");
           l->debug(text);
       }

       static void meth_751() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_751");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_751");
           l->debug(text);
       }

       static void meth_752() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_752");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_752");
           l->debug(text);
       }

       static void meth_753() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_753");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_753");
           l->debug(text);
       }

       static void meth_754() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_754");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_754");
           l->debug(text);
       }

       static void meth_755() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_755");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_755");
           l->debug(text);
       }

       static void meth_756() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_756");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_756");
           l->debug(text);
       }

       static void meth_757() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_757");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_757");
           l->debug(text);
       }

       static void meth_758() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_758");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_758");
           l->debug(text);
       }

       static void meth_759() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_759");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_759");
           l->debug(text);
       }

       static void meth_760() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_760");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_760");
           l->debug(text);
       }

       static void meth_761() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_761");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_761");
           l->debug(text);
       }

       static void meth_762() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_762");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_762");
           l->debug(text);
       }

       static void meth_763() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_763");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_763");
           l->debug(text);
       }

       static void meth_764() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_764");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_764");
           l->debug(text);
       }

       static void meth_765() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_765");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_765");
           l->debug(text);
       }

       static void meth_766() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_766");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_766");
           l->debug(text);
       }

       static void meth_767() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_767");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_767");
           l->debug(text);
       }

       static void meth_768() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_768");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_768");
           l->debug(text);
       }

       static void meth_769() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_769");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_769");
           l->debug(text);
       }

       static void meth_770() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_770");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_770");
           l->debug(text);
       }

       static void meth_771() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_771");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_771");
           l->debug(text);
       }

       static void meth_772() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_772");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_772");
           l->debug(text);
       }

       static void meth_773() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_773");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_773");
           l->debug(text);
       }

       static void meth_774() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_774");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_774");
           l->debug(text);
       }

       static void meth_775() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_775");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_775");
           l->debug(text);
       }

       static void meth_776() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_776");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_776");
           l->debug(text);
       }

       static void meth_777() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_777");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_777");
           l->debug(text);
       }

       static void meth_778() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_778");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_778");
           l->debug(text);
       }

       static void meth_779() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_779");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_779");
           l->debug(text);
       }

       static void meth_780() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_780");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_780");
           l->debug(text);
       }

       static void meth_781() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_781");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_781");
           l->debug(text);
       }

       static void meth_782() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_782");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_782");
           l->debug(text);
       }

       static void meth_783() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_783");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_783");
           l->debug(text);
       }

       static void meth_784() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_784");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_784");
           l->debug(text);
       }

       static void meth_785() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_785");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_785");
           l->debug(text);
       }

       static void meth_786() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_786");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_786");
           l->debug(text);
       }

       static void meth_787() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_787");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_787");
           l->debug(text);
       }

       static void meth_788() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_788");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_788");
           l->debug(text);
       }

       static void meth_789() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_789");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_789");
           l->debug(text);
       }

       static void meth_790() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_790");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_790");
           l->debug(text);
       }

       static void meth_791() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_791");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_791");
           l->debug(text);
       }

       static void meth_792() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_792");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_792");
           l->debug(text);
       }

       static void meth_793() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_793");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_793");
           l->debug(text);
       }

       static void meth_794() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_794");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_794");
           l->debug(text);
       }

       static void meth_795() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_795");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_795");
           l->debug(text);
       }

       static void meth_796() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_796");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_796");
           l->debug(text);
       }

       static void meth_797() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_797");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_797");
           l->debug(text);
       }

       static void meth_798() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_798");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_798");
           l->debug(text);
       }

       static void meth_799() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_799");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_799");
           l->debug(text);
       }

       static void meth_800() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_800");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_800");
           l->debug(text);
       }

       static void meth_801() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_801");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_801");
           l->debug(text);
       }

       static void meth_802() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_802");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_802");
           l->debug(text);
       }

       static void meth_803() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_803");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_803");
           l->debug(text);
       }

       static void meth_804() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_804");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_804");
           l->debug(text);
       }

       static void meth_805() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_805");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_805");
           l->debug(text);
       }

       static void meth_806() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_806");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_806");
           l->debug(text);
       }

       static void meth_807() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_807");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_807");
           l->debug(text);
       }

       static void meth_808() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_808");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_808");
           l->debug(text);
       }

       static void meth_809() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_809");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_809");
           l->debug(text);
       }

       static void meth_810() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_810");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_810");
           l->debug(text);
       }

       static void meth_811() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_811");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_811");
           l->debug(text);
       }

       static void meth_812() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_812");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_812");
           l->debug(text);
       }

       static void meth_813() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_813");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_813");
           l->debug(text);
       }

       static void meth_814() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_814");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_814");
           l->debug(text);
       }

       static void meth_815() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_815");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_815");
           l->debug(text);
       }

       static void meth_816() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_816");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_816");
           l->debug(text);
       }

       static void meth_817() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_817");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_817");
           l->debug(text);
       }

       static void meth_818() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_818");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_818");
           l->debug(text);
       }

       static void meth_819() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_819");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_819");
           l->debug(text);
       }

       static void meth_820() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_820");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_820");
           l->debug(text);
       }

       static void meth_821() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_821");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_821");
           l->debug(text);
       }

       static void meth_822() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_822");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_822");
           l->debug(text);
       }

       static void meth_823() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_823");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_823");
           l->debug(text);
       }

       static void meth_824() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_824");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_824");
           l->debug(text);
       }

       static void meth_825() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_825");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_825");
           l->debug(text);
       }

       static void meth_826() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_826");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_826");
           l->debug(text);
       }

       static void meth_827() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_827");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_827");
           l->debug(text);
       }

       static void meth_828() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_828");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_828");
           l->debug(text);
       }

       static void meth_829() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_829");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_829");
           l->debug(text);
       }

       static void meth_830() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_830");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_830");
           l->debug(text);
       }

       static void meth_831() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_831");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_831");
           l->debug(text);
       }

       static void meth_832() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_832");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_832");
           l->debug(text);
       }

       static void meth_833() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_833");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_833");
           l->debug(text);
       }

       static void meth_834() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_834");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_834");
           l->debug(text);
       }

       static void meth_835() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_835");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_835");
           l->debug(text);
       }

       static void meth_836() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_836");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_836");
           l->debug(text);
       }

       static void meth_837() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_837");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_837");
           l->debug(text);
       }

       static void meth_838() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_838");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_838");
           l->debug(text);
       }

       static void meth_839() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_839");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_839");
           l->debug(text);
       }

       static void meth_840() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_840");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_840");
           l->debug(text);
       }

       static void meth_841() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_841");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_841");
           l->debug(text);
       }

       static void meth_842() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_842");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_842");
           l->debug(text);
       }

       static void meth_843() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_843");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_843");
           l->debug(text);
       }

       static void meth_844() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_844");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_844");
           l->debug(text);
       }

       static void meth_845() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_845");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_845");
           l->debug(text);
       }

       static void meth_846() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_846");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_846");
           l->debug(text);
       }

       static void meth_847() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_847");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_847");
           l->debug(text);
       }

       static void meth_848() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_848");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_848");
           l->debug(text);
       }

       static void meth_849() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_849");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_849");
           l->debug(text);
       }

       static void meth_850() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_850");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_850");
           l->debug(text);
       }

       static void meth_851() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_851");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_851");
           l->debug(text);
       }

       static void meth_852() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_852");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_852");
           l->debug(text);
       }

       static void meth_853() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_853");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_853");
           l->debug(text);
       }

       static void meth_854() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_854");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_854");
           l->debug(text);
       }

       static void meth_855() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_855");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_855");
           l->debug(text);
       }

       static void meth_856() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_856");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_856");
           l->debug(text);
       }

       static void meth_857() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_857");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_857");
           l->debug(text);
       }

       static void meth_858() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_858");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_858");
           l->debug(text);
       }

       static void meth_859() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_859");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_859");
           l->debug(text);
       }

       static void meth_860() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_860");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_860");
           l->debug(text);
       }

       static void meth_861() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_861");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_861");
           l->debug(text);
       }

       static void meth_862() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_862");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_862");
           l->debug(text);
       }

       static void meth_863() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_863");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_863");
           l->debug(text);
       }

       static void meth_864() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_864");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_864");
           l->debug(text);
       }

       static void meth_865() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_865");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_865");
           l->debug(text);
       }

       static void meth_866() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_866");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_866");
           l->debug(text);
       }

       static void meth_867() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_867");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_867");
           l->debug(text);
       }

       static void meth_868() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_868");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_868");
           l->debug(text);
       }

       static void meth_869() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_869");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_869");
           l->debug(text);
       }

       static void meth_870() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_870");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_870");
           l->debug(text);
       }

       static void meth_871() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_871");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_871");
           l->debug(text);
       }

       static void meth_872() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_872");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_872");
           l->debug(text);
       }

       static void meth_873() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_873");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_873");
           l->debug(text);
       }

       static void meth_874() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_874");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_874");
           l->debug(text);
       }

       static void meth_875() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_875");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_875");
           l->debug(text);
       }

       static void meth_876() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_876");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_876");
           l->debug(text);
       }

       static void meth_877() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_877");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_877");
           l->debug(text);
       }

       static void meth_878() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_878");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_878");
           l->debug(text);
       }

       static void meth_879() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_879");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_879");
           l->debug(text);
       }

       static void meth_880() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_880");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_880");
           l->debug(text);
       }

       static void meth_881() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_881");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_881");
           l->debug(text);
       }

       static void meth_882() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_882");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_882");
           l->debug(text);
       }

       static void meth_883() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_883");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_883");
           l->debug(text);
       }

       static void meth_884() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_884");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_884");
           l->debug(text);
       }

       static void meth_885() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_885");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_885");
           l->debug(text);
       }

       static void meth_886() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_886");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_886");
           l->debug(text);
       }

       static void meth_887() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_887");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_887");
           l->debug(text);
       }

       static void meth_888() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_888");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_888");
           l->debug(text);
       }

       static void meth_889() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_889");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_889");
           l->debug(text);
       }

       static void meth_890() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_890");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_890");
           l->debug(text);
       }

       static void meth_891() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_891");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_891");
           l->debug(text);
       }

       static void meth_892() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_892");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_892");
           l->debug(text);
       }

       static void meth_893() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_893");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_893");
           l->debug(text);
       }

       static void meth_894() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_894");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_894");
           l->debug(text);
       }

       static void meth_895() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_895");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_895");
           l->debug(text);
       }

       static void meth_896() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_896");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_896");
           l->debug(text);
       }

       static void meth_897() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_897");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_897");
           l->debug(text);
       }

       static void meth_898() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_898");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_898");
           l->debug(text);
       }

       static void meth_899() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_899");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_899");
           l->debug(text);
       }

       static void meth_900() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_900");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_900");
           l->debug(text);
       }

       static void meth_901() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_901");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_901");
           l->debug(text);
       }

       static void meth_902() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_902");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_902");
           l->debug(text);
       }

       static void meth_903() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_903");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_903");
           l->debug(text);
       }

       static void meth_904() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_904");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_904");
           l->debug(text);
       }

       static void meth_905() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_905");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_905");
           l->debug(text);
       }

       static void meth_906() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_906");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_906");
           l->debug(text);
       }

       static void meth_907() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_907");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_907");
           l->debug(text);
       }

       static void meth_908() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_908");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_908");
           l->debug(text);
       }

       static void meth_909() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_909");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_909");
           l->debug(text);
       }

       static void meth_910() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_910");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_910");
           l->debug(text);
       }

       static void meth_911() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_911");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_911");
           l->debug(text);
       }

       static void meth_912() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_912");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_912");
           l->debug(text);
       }

       static void meth_913() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_913");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_913");
           l->debug(text);
       }

       static void meth_914() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_914");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_914");
           l->debug(text);
       }

       static void meth_915() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_915");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_915");
           l->debug(text);
       }

       static void meth_916() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_916");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_916");
           l->debug(text);
       }

       static void meth_917() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_917");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_917");
           l->debug(text);
       }

       static void meth_918() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_918");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_918");
           l->debug(text);
       }

       static void meth_919() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_919");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_919");
           l->debug(text);
       }

       static void meth_920() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_920");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_920");
           l->debug(text);
       }

       static void meth_921() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_921");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_921");
           l->debug(text);
       }

       static void meth_922() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_922");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_922");
           l->debug(text);
       }

       static void meth_923() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_923");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_923");
           l->debug(text);
       }

       static void meth_924() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_924");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_924");
           l->debug(text);
       }

       static void meth_925() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_925");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_925");
           l->debug(text);
       }

       static void meth_926() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_926");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_926");
           l->debug(text);
       }

       static void meth_927() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_927");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_927");
           l->debug(text);
       }

       static void meth_928() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_928");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_928");
           l->debug(text);
       }

       static void meth_929() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_929");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_929");
           l->debug(text);
       }

       static void meth_930() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_930");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_930");
           l->debug(text);
       }

       static void meth_931() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_931");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_931");
           l->debug(text);
       }

       static void meth_932() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_932");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_932");
           l->debug(text);
       }

       static void meth_933() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_933");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_933");
           l->debug(text);
       }

       static void meth_934() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_934");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_934");
           l->debug(text);
       }

       static void meth_935() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_935");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_935");
           l->debug(text);
       }

       static void meth_936() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_936");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_936");
           l->debug(text);
       }

       static void meth_937() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_937");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_937");
           l->debug(text);
       }

       static void meth_938() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_938");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_938");
           l->debug(text);
       }

       static void meth_939() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_939");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_939");
           l->debug(text);
       }

       static void meth_940() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_940");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_940");
           l->debug(text);
       }

       static void meth_941() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_941");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_941");
           l->debug(text);
       }

       static void meth_942() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_942");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_942");
           l->debug(text);
       }

       static void meth_943() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_943");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_943");
           l->debug(text);
       }

       static void meth_944() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_944");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_944");
           l->debug(text);
       }

       static void meth_945() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_945");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_945");
           l->debug(text);
       }

       static void meth_946() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_946");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_946");
           l->debug(text);
       }

       static void meth_947() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_947");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_947");
           l->debug(text);
       }

       static void meth_948() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_948");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_948");
           l->debug(text);
       }

       static void meth_949() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_949");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_949");
           l->debug(text);
       }

       static void meth_950() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_950");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_950");
           l->debug(text);
       }

       static void meth_951() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_951");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_951");
           l->debug(text);
       }

       static void meth_952() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_952");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_952");
           l->debug(text);
       }

       static void meth_953() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_953");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_953");
           l->debug(text);
       }

       static void meth_954() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_954");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_954");
           l->debug(text);
       }

       static void meth_955() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_955");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_955");
           l->debug(text);
       }

       static void meth_956() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_956");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_956");
           l->debug(text);
       }

       static void meth_957() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_957");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_957");
           l->debug(text);
       }

       static void meth_958() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_958");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_958");
           l->debug(text);
       }

       static void meth_959() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_959");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_959");
           l->debug(text);
       }

       static void meth_960() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_960");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_960");
           l->debug(text);
       }

       static void meth_961() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_961");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_961");
           l->debug(text);
       }

       static void meth_962() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_962");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_962");
           l->debug(text);
       }

       static void meth_963() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_963");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_963");
           l->debug(text);
       }

       static void meth_964() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_964");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_964");
           l->debug(text);
       }

       static void meth_965() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_965");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_965");
           l->debug(text);
       }

       static void meth_966() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_966");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_966");
           l->debug(text);
       }

       static void meth_967() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_967");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_967");
           l->debug(text);
       }

       static void meth_968() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_968");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_968");
           l->debug(text);
       }

       static void meth_969() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_969");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_969");
           l->debug(text);
       }

       static void meth_970() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_970");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_970");
           l->debug(text);
       }

       static void meth_971() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_971");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_971");
           l->debug(text);
       }

       static void meth_972() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_972");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_972");
           l->debug(text);
       }

       static void meth_973() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_973");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_973");
           l->debug(text);
       }

       static void meth_974() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_974");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_974");
           l->debug(text);
       }

       static void meth_975() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_975");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_975");
           l->debug(text);
       }

       static void meth_976() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_976");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_976");
           l->debug(text);
       }

       static void meth_977() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_977");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_977");
           l->debug(text);
       }

       static void meth_978() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_978");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_978");
           l->debug(text);
       }

       static void meth_979() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_979");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_979");
           l->debug(text);
       }

       static void meth_980() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_980");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_980");
           l->debug(text);
       }

       static void meth_981() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_981");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_981");
           l->debug(text);
       }

       static void meth_982() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_982");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_982");
           l->debug(text);
       }

       static void meth_983() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_983");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_983");
           l->debug(text);
       }

       static void meth_984() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_984");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_984");
           l->debug(text);
       }

       static void meth_985() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_985");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_985");
           l->debug(text);
       }

       static void meth_986() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_986");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_986");
           l->debug(text);
       }

       static void meth_987() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_987");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_987");
           l->debug(text);
       }

       static void meth_988() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_988");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_988");
           l->debug(text);
       }

       static void meth_989() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_989");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_989");
           l->debug(text);
       }

       static void meth_990() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_990");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_990");
           l->debug(text);
       }

       static void meth_991() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_991");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_991");
           l->debug(text);
       }

       static void meth_992() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_992");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_992");
           l->debug(text);
       }

       static void meth_993() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_993");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_993");
           l->debug(text);
       }

       static void meth_994() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_994");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_994");
           l->debug(text);
       }

       static void meth_995() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_995");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_995");
           l->debug(text);
       }

       static void meth_996() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_996");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_996");
           l->debug(text);
       }

       static void meth_997() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_997");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_997");
           l->debug(text);
       }

       static void meth_998() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_998");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_998");
           l->debug(text);
       }

       static void meth_999() {
           static LoggerPtr l = Logger::getLogger("log4cxx.LoggerTest.meth_999");

           char text[100];
           sprintf(text, "log4cxx.LoggerTest.meth_999");
           l->debug(text);
       }


       static void * LOG4CXX_THREAD_FUNC runStatic(log4cxx_thread_t* thread, void* data) {
           meth_0();
           meth_1();
           meth_2();
           meth_3();
           meth_4();
           meth_5();
           meth_6();
           meth_7();
           meth_8();
           meth_9();
           meth_10();
           meth_11();
           meth_12();
           meth_13();
           meth_14();
           meth_15();
           meth_16();
           meth_17();
           meth_18();
           meth_19();
           meth_20();
           meth_21();
           meth_22();
           meth_23();
           meth_24();
           meth_25();
           meth_26();
           meth_27();
           meth_28();
           meth_29();
           meth_30();
           meth_31();
           meth_32();
           meth_33();
           meth_34();
           meth_35();
           meth_36();
           meth_37();
           meth_38();
           meth_39();
           meth_40();
           meth_41();
           meth_42();
           meth_43();
           meth_44();
           meth_45();
           meth_46();
           meth_47();
           meth_48();
           meth_49();
           meth_50();
           meth_51();
           meth_52();
           meth_53();
           meth_54();
           meth_55();
           meth_56();
           meth_57();
           meth_58();
           meth_59();
           meth_60();
           meth_61();
           meth_62();
           meth_63();
           meth_64();
           meth_65();
           meth_66();
           meth_67();
           meth_68();
           meth_69();
           meth_70();
           meth_71();
           meth_72();
           meth_73();
           meth_74();
           meth_75();
           meth_76();
           meth_77();
           meth_78();
           meth_79();
           meth_80();
           meth_81();
           meth_82();
           meth_83();
           meth_84();
           meth_85();
           meth_86();
           meth_87();
           meth_88();
           meth_89();
           meth_90();
           meth_91();
           meth_92();
           meth_93();
           meth_94();
           meth_95();
           meth_96();
           meth_97();
           meth_98();
           meth_99();
           meth_100();
           meth_101();
           meth_102();
           meth_103();
           meth_104();
           meth_105();
           meth_106();
           meth_107();
           meth_108();
           meth_109();
           meth_110();
           meth_111();
           meth_112();
           meth_113();
           meth_114();
           meth_115();
           meth_116();
           meth_117();
           meth_118();
           meth_119();
           meth_120();
           meth_121();
           meth_122();
           meth_123();
           meth_124();
           meth_125();
           meth_126();
           meth_127();
           meth_128();
           meth_129();
           meth_130();
           meth_131();
           meth_132();
           meth_133();
           meth_134();
           meth_135();
           meth_136();
           meth_137();
           meth_138();
           meth_139();
           meth_140();
           meth_141();
           meth_142();
           meth_143();
           meth_144();
           meth_145();
           meth_146();
           meth_147();
           meth_148();
           meth_149();
           meth_150();
           meth_151();
           meth_152();
           meth_153();
           meth_154();
           meth_155();
           meth_156();
           meth_157();
           meth_158();
           meth_159();
           meth_160();
           meth_161();
           meth_162();
           meth_163();
           meth_164();
           meth_165();
           meth_166();
           meth_167();
           meth_168();
           meth_169();
           meth_170();
           meth_171();
           meth_172();
           meth_173();
           meth_174();
           meth_175();
           meth_176();
           meth_177();
           meth_178();
           meth_179();
           meth_180();
           meth_181();
           meth_182();
           meth_183();
           meth_184();
           meth_185();
           meth_186();
           meth_187();
           meth_188();
           meth_189();
           meth_190();
           meth_191();
           meth_192();
           meth_193();
           meth_194();
           meth_195();
           meth_196();
           meth_197();
           meth_198();
           meth_199();
           meth_200();
           meth_201();
           meth_202();
           meth_203();
           meth_204();
           meth_205();
           meth_206();
           meth_207();
           meth_208();
           meth_209();
           meth_210();
           meth_211();
           meth_212();
           meth_213();
           meth_214();
           meth_215();
           meth_216();
           meth_217();
           meth_218();
           meth_219();
           meth_220();
           meth_221();
           meth_222();
           meth_223();
           meth_224();
           meth_225();
           meth_226();
           meth_227();
           meth_228();
           meth_229();
           meth_230();
           meth_231();
           meth_232();
           meth_233();
           meth_234();
           meth_235();
           meth_236();
           meth_237();
           meth_238();
           meth_239();
           meth_240();
           meth_241();
           meth_242();
           meth_243();
           meth_244();
           meth_245();
           meth_246();
           meth_247();
           meth_248();
           meth_249();
           meth_250();
           meth_251();
           meth_252();
           meth_253();
           meth_254();
           meth_255();
           meth_256();
           meth_257();
           meth_258();
           meth_259();
           meth_260();
           meth_261();
           meth_262();
           meth_263();
           meth_264();
           meth_265();
           meth_266();
           meth_267();
           meth_268();
           meth_269();
           meth_270();
           meth_271();
           meth_272();
           meth_273();
           meth_274();
           meth_275();
           meth_276();
           meth_277();
           meth_278();
           meth_279();
           meth_280();
           meth_281();
           meth_282();
           meth_283();
           meth_284();
           meth_285();
           meth_286();
           meth_287();
           meth_288();
           meth_289();
           meth_290();
           meth_291();
           meth_292();
           meth_293();
           meth_294();
           meth_295();
           meth_296();
           meth_297();
           meth_298();
           meth_299();
           meth_300();
           meth_301();
           meth_302();
           meth_303();
           meth_304();
           meth_305();
           meth_306();
           meth_307();
           meth_308();
           meth_309();
           meth_310();
           meth_311();
           meth_312();
           meth_313();
           meth_314();
           meth_315();
           meth_316();
           meth_317();
           meth_318();
           meth_319();
           meth_320();
           meth_321();
           meth_322();
           meth_323();
           meth_324();
           meth_325();
           meth_326();
           meth_327();
           meth_328();
           meth_329();
           meth_330();
           meth_331();
           meth_332();
           meth_333();
           meth_334();
           meth_335();
           meth_336();
           meth_337();
           meth_338();
           meth_339();
           meth_340();
           meth_341();
           meth_342();
           meth_343();
           meth_344();
           meth_345();
           meth_346();
           meth_347();
           meth_348();
           meth_349();
           meth_350();
           meth_351();
           meth_352();
           meth_353();
           meth_354();
           meth_355();
           meth_356();
           meth_357();
           meth_358();
           meth_359();
           meth_360();
           meth_361();
           meth_362();
           meth_363();
           meth_364();
           meth_365();
           meth_366();
           meth_367();
           meth_368();
           meth_369();
           meth_370();
           meth_371();
           meth_372();
           meth_373();
           meth_374();
           meth_375();
           meth_376();
           meth_377();
           meth_378();
           meth_379();
           meth_380();
           meth_381();
           meth_382();
           meth_383();
           meth_384();
           meth_385();
           meth_386();
           meth_387();
           meth_388();
           meth_389();
           meth_390();
           meth_391();
           meth_392();
           meth_393();
           meth_394();
           meth_395();
           meth_396();
           meth_397();
           meth_398();
           meth_399();
           meth_400();
           meth_401();
           meth_402();
           meth_403();
           meth_404();
           meth_405();
           meth_406();
           meth_407();
           meth_408();
           meth_409();
           meth_410();
           meth_411();
           meth_412();
           meth_413();
           meth_414();
           meth_415();
           meth_416();
           meth_417();
           meth_418();
           meth_419();
           meth_420();
           meth_421();
           meth_422();
           meth_423();
           meth_424();
           meth_425();
           meth_426();
           meth_427();
           meth_428();
           meth_429();
           meth_430();
           meth_431();
           meth_432();
           meth_433();
           meth_434();
           meth_435();
           meth_436();
           meth_437();
           meth_438();
           meth_439();
           meth_440();
           meth_441();
           meth_442();
           meth_443();
           meth_444();
           meth_445();
           meth_446();
           meth_447();
           meth_448();
           meth_449();
           meth_450();
           meth_451();
           meth_452();
           meth_453();
           meth_454();
           meth_455();
           meth_456();
           meth_457();
           meth_458();
           meth_459();
           meth_460();
           meth_461();
           meth_462();
           meth_463();
           meth_464();
           meth_465();
           meth_466();
           meth_467();
           meth_468();
           meth_469();
           meth_470();
           meth_471();
           meth_472();
           meth_473();
           meth_474();
           meth_475();
           meth_476();
           meth_477();
           meth_478();
           meth_479();
           meth_480();
           meth_481();
           meth_482();
           meth_483();
           meth_484();
           meth_485();
           meth_486();
           meth_487();
           meth_488();
           meth_489();
           meth_490();
           meth_491();
           meth_492();
           meth_493();
           meth_494();
           meth_495();
           meth_496();
           meth_497();
           meth_498();
           meth_499();
           meth_500();
           meth_501();
           meth_502();
           meth_503();
           meth_504();
           meth_505();
           meth_506();
           meth_507();
           meth_508();
           meth_509();
           meth_510();
           meth_511();
           meth_512();
           meth_513();
           meth_514();
           meth_515();
           meth_516();
           meth_517();
           meth_518();
           meth_519();
           meth_520();
           meth_521();
           meth_522();
           meth_523();
           meth_524();
           meth_525();
           meth_526();
           meth_527();
           meth_528();
           meth_529();
           meth_530();
           meth_531();
           meth_532();
           meth_533();
           meth_534();
           meth_535();
           meth_536();
           meth_537();
           meth_538();
           meth_539();
           meth_540();
           meth_541();
           meth_542();
           meth_543();
           meth_544();
           meth_545();
           meth_546();
           meth_547();
           meth_548();
           meth_549();
           meth_550();
           meth_551();
           meth_552();
           meth_553();
           meth_554();
           meth_555();
           meth_556();
           meth_557();
           meth_558();
           meth_559();
           meth_560();
           meth_561();
           meth_562();
           meth_563();
           meth_564();
           meth_565();
           meth_566();
           meth_567();
           meth_568();
           meth_569();
           meth_570();
           meth_571();
           meth_572();
           meth_573();
           meth_574();
           meth_575();
           meth_576();
           meth_577();
           meth_578();
           meth_579();
           meth_580();
           meth_581();
           meth_582();
           meth_583();
           meth_584();
           meth_585();
           meth_586();
           meth_587();
           meth_588();
           meth_589();
           meth_590();
           meth_591();
           meth_592();
           meth_593();
           meth_594();
           meth_595();
           meth_596();
           meth_597();
           meth_598();
           meth_599();
           meth_600();
           meth_601();
           meth_602();
           meth_603();
           meth_604();
           meth_605();
           meth_606();
           meth_607();
           meth_608();
           meth_609();
           meth_610();
           meth_611();
           meth_612();
           meth_613();
           meth_614();
           meth_615();
           meth_616();
           meth_617();
           meth_618();
           meth_619();
           meth_620();
           meth_621();
           meth_622();
           meth_623();
           meth_624();
           meth_625();
           meth_626();
           meth_627();
           meth_628();
           meth_629();
           meth_630();
           meth_631();
           meth_632();
           meth_633();
           meth_634();
           meth_635();
           meth_636();
           meth_637();
           meth_638();
           meth_639();
           meth_640();
           meth_641();
           meth_642();
           meth_643();
           meth_644();
           meth_645();
           meth_646();
           meth_647();
           meth_648();
           meth_649();
           meth_650();
           meth_651();
           meth_652();
           meth_653();
           meth_654();
           meth_655();
           meth_656();
           meth_657();
           meth_658();
           meth_659();
           meth_660();
           meth_661();
           meth_662();
           meth_663();
           meth_664();
           meth_665();
           meth_666();
           meth_667();
           meth_668();
           meth_669();
           meth_670();
           meth_671();
           meth_672();
           meth_673();
           meth_674();
           meth_675();
           meth_676();
           meth_677();
           meth_678();
           meth_679();
           meth_680();
           meth_681();
           meth_682();
           meth_683();
           meth_684();
           meth_685();
           meth_686();
           meth_687();
           meth_688();
           meth_689();
           meth_690();
           meth_691();
           meth_692();
           meth_693();
           meth_694();
           meth_695();
           meth_696();
           meth_697();
           meth_698();
           meth_699();
           meth_700();
           meth_701();
           meth_702();
           meth_703();
           meth_704();
           meth_705();
           meth_706();
           meth_707();
           meth_708();
           meth_709();
           meth_710();
           meth_711();
           meth_712();
           meth_713();
           meth_714();
           meth_715();
           meth_716();
           meth_717();
           meth_718();
           meth_719();
           meth_720();
           meth_721();
           meth_722();
           meth_723();
           meth_724();
           meth_725();
           meth_726();
           meth_727();
           meth_728();
           meth_729();
           meth_730();
           meth_731();
           meth_732();
           meth_733();
           meth_734();
           meth_735();
           meth_736();
           meth_737();
           meth_738();
           meth_739();
           meth_740();
           meth_741();
           meth_742();
           meth_743();
           meth_744();
           meth_745();
           meth_746();
           meth_747();
           meth_748();
           meth_749();
           meth_750();
           meth_751();
           meth_752();
           meth_753();
           meth_754();
           meth_755();
           meth_756();
           meth_757();
           meth_758();
           meth_759();
           meth_760();
           meth_761();
           meth_762();
           meth_763();
           meth_764();
           meth_765();
           meth_766();
           meth_767();
           meth_768();
           meth_769();
           meth_770();
           meth_771();
           meth_772();
           meth_773();
           meth_774();
           meth_775();
           meth_776();
           meth_777();
           meth_778();
           meth_779();
           meth_780();
           meth_781();
           meth_782();
           meth_783();
           meth_784();
           meth_785();
           meth_786();
           meth_787();
           meth_788();
           meth_789();
           meth_790();
           meth_791();
           meth_792();
           meth_793();
           meth_794();
           meth_795();
           meth_796();
           meth_797();
           meth_798();
           meth_799();
           meth_800();
           meth_801();
           meth_802();
           meth_803();
           meth_804();
           meth_805();
           meth_806();
           meth_807();
           meth_808();
           meth_809();
           meth_810();
           meth_811();
           meth_812();
           meth_813();
           meth_814();
           meth_815();
           meth_816();
           meth_817();
           meth_818();
           meth_819();
           meth_820();
           meth_821();
           meth_822();
           meth_823();
           meth_824();
           meth_825();
           meth_826();
           meth_827();
           meth_828();
           meth_829();
           meth_830();
           meth_831();
           meth_832();
           meth_833();
           meth_834();
           meth_835();
           meth_836();
           meth_837();
           meth_838();
           meth_839();
           meth_840();
           meth_841();
           meth_842();
           meth_843();
           meth_844();
           meth_845();
           meth_846();
           meth_847();
           meth_848();
           meth_849();
           meth_850();
           meth_851();
           meth_852();
           meth_853();
           meth_854();
           meth_855();
           meth_856();
           meth_857();
           meth_858();
           meth_859();
           meth_860();
           meth_861();
           meth_862();
           meth_863();
           meth_864();
           meth_865();
           meth_866();
           meth_867();
           meth_868();
           meth_869();
           meth_870();
           meth_871();
           meth_872();
           meth_873();
           meth_874();
           meth_875();
           meth_876();
           meth_877();
           meth_878();
           meth_879();
           meth_880();
           meth_881();
           meth_882();
           meth_883();
           meth_884();
           meth_885();
           meth_886();
           meth_887();
           meth_888();
           meth_889();
           meth_890();
           meth_891();
           meth_892();
           meth_893();
           meth_894();
           meth_895();
           meth_896();
           meth_897();
           meth_898();
           meth_899();
           meth_900();
           meth_901();
           meth_902();
           meth_903();
           meth_904();
           meth_905();
           meth_906();
           meth_907();
           meth_908();
           meth_909();
           meth_910();
           meth_911();
           meth_912();
           meth_913();
           meth_914();
           meth_915();
           meth_916();
           meth_917();
           meth_918();
           meth_919();
           meth_920();
           meth_921();
           meth_922();
           meth_923();
           meth_924();
           meth_925();
           meth_926();
           meth_927();
           meth_928();
           meth_929();
           meth_930();
           meth_931();
           meth_932();
           meth_933();
           meth_934();
           meth_935();
           meth_936();
           meth_937();
           meth_938();
           meth_939();
           meth_940();
           meth_941();
           meth_942();
           meth_943();
           meth_944();
           meth_945();
           meth_946();
           meth_947();
           meth_948();
           meth_949();
           meth_950();
           meth_951();
           meth_952();
           meth_953();
           meth_954();
           meth_955();
           meth_956();
           meth_957();
           meth_958();
           meth_959();
           meth_960();
           meth_961();
           meth_962();
           meth_963();
           meth_964();
           meth_965();
           meth_966();
           meth_967();
           meth_968();
           meth_969();
           meth_970();
           meth_971();
           meth_972();
           meth_973();
           meth_974();
           meth_975();
           meth_976();
           meth_977();
           meth_978();
           meth_979();
           meth_980();
           meth_981();
           meth_982();
           meth_983();
           meth_984();
           meth_985();
           meth_986();
           meth_987();
           meth_988();
           meth_989();
           meth_990();
           meth_991();
           meth_992();
           meth_993();
           meth_994();
           meth_995();
           meth_996();
           meth_997();
           meth_998();
           meth_999();
       }


};

CPPUNIT_TEST_SUITE_REGISTRATION(ThreadTest);

