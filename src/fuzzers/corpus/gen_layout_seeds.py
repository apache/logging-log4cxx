#!/usr/bin/env python3
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Deterministic seed generator for the checked-in fuzzing seed corpora
in src/fuzzers/corpus.

Produces libFuzzer seed files shaped for the FuzzedDataProvider-based
layout harnesses whose production corpus backups are missing
(HTMLLayoutFuzzer-utf-8, XMLLayoutFuzzer-utf-8, XMLLayoutFuzzer-wchar_t,
TimeBasedRollingPolicyFuzzer-utf-8).  src/fuzzers/bash/oss-fuzz-build.sh
packages the generated files into per-target seed corpus archives; run
this script from the repository root to regenerate them:

    python3 src/fuzzers/corpus/gen_layout_seeds.py src/fuzzers/corpus

FuzzedDataProvider contract used by those harnesses:
  * ConsumeRandomLengthString() consumes from the FRONT and stops at a
    backslash followed by any other byte ("\\\\." encodes a literal backslash);
  * ConsumeBool()/ConsumeIntegral consume bytes from the BACK.
So a seed is: <front fields separated by \\x5c\\x00> + <back bytes>.
"""

import os
import sys

SEP = b'\\\x00'          # terminator consumed by ConsumeRandomLengthString


def front(*fields):
    out = bytearray()
    for f in fields:
        f = f.replace(b'\\', b'\\\\')
        out += f + SEP
    return bytes(out)


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)


def main(out_root):
    html_dir = os.path.join(out_root, 'html-utf8')
    xml_dir = os.path.join(out_root, 'xml-utf8')
    xmlw_dir = os.path.join(out_root, 'xml-wchar')
    tbrp_dir = os.path.join(out_root, 'tbrp-utf8')

    logger = b'fuzz.logger'
    ndc = b'fuzz.ndc.stack'
    keys_vals = [b'k1', b'v1', b'k2', b'v2', b'k3', b'v3', b'k4', b'v4']
    entity = b'<log><event attr="a &amp; b">text &lt;here&gt;</event></log>'
    longmsg = (b'message with entities &amp; &lt; &gt; &quot; and control \x01\x02 bytes '
               + b'x' * 512 + b' end')
    utf8 = 'unicode héllo wörld 日本語'.encode('utf-8')

    # HTMLLayoutFuzzer: 10 front fields (k1,v1,k2,v2,k3,v3,k4,v4,ndc,logger)
    # then remaining bytes as content; 3 back bytes for the bools.
    html_seeds = {
        'seed-html-entities': front(*keys_vals, ndc, logger) + entity + b'\x01\x01\x01',
        'seed-html-long': front(*keys_vals, ndc, logger) + longmsg + b'\x00\x00\x00',
        'seed-html-unicode': front(*keys_vals, ndc, logger) + utf8 + b'\x01\x00\x01',
        'seed-html-titled': front(b't1', b'w1', b't2', b'w2', b't3', b'w3', b't4', b'w4',
                                  b'<title>Title &amp; more</title>',
                                  b'<h1>Header</h1>') + entity + b'\x01\x01\x00',
        'seed-html-quotes': front(b'k"q', b'v\\b', b'k2', b'v<s>', b'k3', b'v&v', b'k4',
                                  b'v4', ndc, logger) + utf8 + b'\x00\x01\x01',
    }
    for name, data in html_seeds.items():
        write(os.path.join(html_dir, name), data)

    # XMLLayoutFuzzer: 8 front fields (key1,val1,key2,val2,ndc,logger,propk,propv)
    # then remaining bytes as content; no back consumption.
    xml_seeds = {
        'seed-xml-entities': front(b'k1', b'v1', b'k2', b'v2', ndc, logger,
                                   b'pk', b'pv') + entity,
        'seed-xml-long': front(b'k1', b'v1', b'k2', b'v2', ndc, logger,
                               b'pk', b'pv') + longmsg,
        'seed-xml-unicode': front(b'k1', b'v1', b'k2', b'v2', ndc, logger,
                                  b'pk', b'pv') + utf8,
        'seed-xml-cdata': front(b'k1', b'v1', b'k2', b'v2', ndc, logger,
                                b'pk', b'pv') + b'<![CDATA[raw & <stuff>]]>',
    }
    for name, data in xml_seeds.items():
        write(os.path.join(xml_dir, name), data)
        write(os.path.join(xmlw_dir, name), data)

    # TimeBasedRollingPolicyFuzzer: front = up to 10 message strings;
    # back = 4-byte int (BufferedSeconds) + 2 bools (usegz read first from
    # program order but bytes come off the end: last byte -> append bool).
    tbrp_seeds = {
        'seed-tbrp-gz-append': b'msg one' + SEP + b'msg two' + SEP
                               + b'filler message three' + SEP
                               + b'\x00\x00\x00\x00' + b'\x01\x01',
        'seed-tbrp-zip-overwrite': b'msg a' + SEP + b'msg b' + SEP
                                   + b'\xff\xff\xff\x7f' + b'\x00\x00',
        'seed-tbrp-longmsg': b'f' * 256 + b'\x00\x00\x00\x00' + b'\x01\x00',
    }
    for name, data in tbrp_seeds.items():
        write(os.path.join(tbrp_dir, name), data)

    total = sum(len(fs) for fs in (html_seeds, xml_seeds, tbrp_seeds))
    print('generated', total, 'seed files under', out_root)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
