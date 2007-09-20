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

package org.apache.logging.log4cxx.helpers;

import junit.framework.TestCase;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Tests java.net.InetAddress to provide baseline
 * for log4cxx's log4cxx::helpers::InetAddress.
 */
public class InetAddressTestCase extends TestCase
{
        /**
         * Tests the InetAddress::getLocalHost() method.
         */
        public void testGetLocalHost() throws Exception {
           InetAddress addr = InetAddress.getLocalHost();

           assertFalse(addr.getHostName().length() == 0);
        }

        /**
         * Tests the InetAddress::getByName() method with the
         * "localhost" host name.
         */
        public void testByNameLocal() throws Exception {
           InetAddress addr = InetAddress.getByName("localhost");

           assertEquals("127.0.0.1", addr.getHostAddress());
           assertFalse(addr.getHostName().length() == 0);
        }

        /**
         * Tests the InetAddress::getAllByName() method with the
         * "localhost" host name.
         */
        public void testAllByNameLocal() throws Exception {
           InetAddress[] addr = InetAddress.getAllByName("localhost");
           assertTrue(addr.length > 0);
        }

        /**
         * Tests the UnknownHostException.
         */
        public void testUnknownHost() {
           try {
            InetAddress.getByName("unknown.invalid");
            fail("Invalid address should result in UnknownHostException");
           } catch(UnknownHostException ex) {
           }
        }

    /**
    * Tests an (likely) unreachable address.
    */
   public void testUnreachable() throws Exception {
       InetAddress addr = InetAddress.getByName("192.168.10.254");
       String addrStr = addr.toString();
       assertEquals(addrStr.length() - 15, addrStr.indexOf("/192.168.10.254"));
   }
}

