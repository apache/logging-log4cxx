/*
 * Copyright 2003,2005 The Apache Software Foundation.
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

 /*
 *
 * This module replaces apr-iconv's iconv_module which
 *  uses dynamic loading of encoding modules.  This
 *  implementation includes all the stock modules
 *  in distinct namespaces (since otherwise they
 *  would introduce conflicting symbols).
 *
 */

#define ICONV_INTERNAL
extern "C" {
  #include <apr.h>
  #include <iconv.h>
}
#include <stdlib.h>

namespace log4cxx {

namespace adobe_stdenc {
  #include "ccs/adobe-stdenc.c"
  #undef NBITS
}
namespace adobe_symbol {
  #include "ccs/adobe-symbol.c"
  #undef NBITS
}
namespace adobe_zdingbats {
  #include "ccs/adobe-zdingbats.c"
  #undef NBITS
}
namespace big5 {
  #include "ccs/big5.c"
  #undef NBITS
}
namespace cns11643_plane14 {
  #include "ccs/cns11643-plane14.c"
  #undef NBITS
  }
namespace cns11643_plane1 {
  #include "ccs/cns11643-plane1.c"
  #undef NBITS
  }
namespace cns11643_plane2 {
  #include "ccs/cns11643-plane2.c"
  #undef NBITS
  }
namespace cp037 {
  #include "ccs/cp037.c"
  #undef NBITS
  }
namespace cp038 {
  #include "ccs/cp038.c"
  }
namespace cp10000 {
  #include "ccs/cp10000.c"
  #undef NBITS
  }
namespace cp10006 {
  #include "ccs/cp10006.c"
  #undef NBITS
  }
namespace cp10007 {
  #include "ccs/cp10007.c"
  #undef NBITS
  }
namespace cp10029 {
  #include "ccs/cp10029.c"
  #undef NBITS
  }
namespace cp1006 {
  #include "ccs/cp1006.c"
  #undef NBITS
  }
namespace cp10079 {
  #include "ccs/cp10079.c"
  #undef NBITS
  }
namespace cp10081 {
  #include "ccs/cp10081.c"
  #undef NBITS
  }
namespace cp1026 {
  #include "ccs/cp1026.c"
  #undef NBITS
  }
namespace cp273 {
  #include "ccs/cp273.c"
  #undef NBITS
  }
namespace cp274 {
  #include "ccs/cp274.c"
  #undef NBITS
  }
namespace cp275 {
  #include "ccs/cp275.c"
  #undef NBITS
  }
namespace cp277 {
  #include "ccs/cp277.c"
  #undef NBITS
  }
namespace cp278 {
  #include "ccs/cp278.c"
  #undef NBITS
  }
namespace cp280 {
  #include "ccs/cp280.c"
  #undef NBITS
  }
namespace cp281 {
  #include "ccs/cp281.c"
  #undef NBITS
  }
namespace cp284 {
  #include "ccs/cp284.c"
  #undef NBITS
  }
namespace cp285 {
  #include "ccs/cp285.c"
  #undef NBITS
  }
namespace cp290 {
  #include "ccs/cp290.c"
  #undef NBITS
  }
namespace cp297 {
  #include "ccs/cp297.c"
  #undef NBITS
  }
namespace cp420 {
  #include "ccs/cp420.c"
  #undef NBITS
  }
namespace cp423 {
  #include "ccs/cp423.c"
  #undef NBITS
  }
namespace cp424 {
  #include "ccs/cp424.c"
  #undef NBITS
  }
namespace cp437 {
  #include "ccs/cp437.c"
  #undef NBITS
  }
namespace cp500 {
  #include "ccs/cp500.c"
  #undef NBITS
  }
namespace cp737 {
  #include "ccs/cp737.c"
  #undef NBITS
  }
namespace cp775 {
  #include "ccs/cp775.c"
  #undef NBITS
  }
namespace cp850 {
  #include "ccs/cp850.c"
  #undef NBITS
  }
namespace cp851 {
  #include "ccs/cp851.c"
  #undef NBITS
  }
namespace cp852 {
  #include "ccs/cp852.c"
  #undef NBITS
  }
namespace cp855 {
  #include "ccs/cp855.c"
  #undef NBITS
  }
namespace cp856 {
  #include "ccs/cp856.c"
  #undef NBITS
  }
namespace cp857 {
  #include "ccs/cp857.c"
  #undef NBITS
  }
namespace cp860 {
  #include "ccs/cp860.c"
  #undef NBITS
  }
namespace cp861 {
  #include "ccs/cp861.c"
  #undef NBITS
  }
namespace cp862 {
  #include "ccs/cp862.c"
  #undef NBITS
  }
namespace cp863 {
  #include "ccs/cp863.c"
  #undef NBITS
  }
namespace cp864 {
  #include "ccs/cp864.c"
  #undef NBITS
  }
namespace cp865 {
  #include "ccs/cp865.c"
  #undef NBITS
  }
namespace cp866 {
  #include "ccs/cp866.c"
  #undef NBITS
  }
namespace cp868 {
  #include "ccs/cp868.c"
  #undef NBITS
  }
namespace cp869 {
  #include "ccs/cp869.c"
  #undef NBITS
  }
namespace cp870 {
  #include "ccs/cp870.c"
  #undef NBITS
  }
namespace cp871 {
  #include "ccs/cp871.c"
  #undef NBITS
  }
namespace cp874 {
  #include "ccs/cp874.c"
  #undef NBITS
  }
namespace cp875 {
  #include "ccs/cp875.c"
  #undef NBITS
  }
namespace cp880 {
  #include "ccs/cp880.c"
  #undef NBITS
  }
namespace cp891 {
  #include "ccs/cp891.c"
  #undef NBITS
  }
namespace cp903 {
  #include "ccs/cp903.c"
  #undef NBITS
  }
namespace cp904 {
  #include "ccs/cp904.c"
  #undef NBITS
  }
namespace cp905 {
  #include "ccs/cp905.c"
  #undef NBITS
  }
namespace cp918 {
  #include "ccs/cp918.c"
  #undef NBITS
  }
namespace cp932 {
  #include "ccs/cp932.c"
  #undef NBITS
  }
namespace cp936 {
  #include "ccs/cp936.c"
  #undef NBITS
  }
namespace cp949 {
  #include "ccs/cp949.c"
  #undef NBITS
  }
namespace cp950 {
  #include "ccs/cp950.c"
  #undef NBITS
  }
namespace dec_mcs {
  #include "ccs/dec-mcs.c"
  #undef NBITS
  }
namespace ebcdic_at_de_a {
  #include "ccs/ebcdic-at-de-a.c"
  #undef NBITS
  }
namespace ebcdic_at_de {
  #include "ccs/ebcdic-at-de.c"
  #undef NBITS
  }
namespace ebcdic_ca_fr {
  #include "ccs/ebcdic-ca-fr.c"
  #undef NBITS
  }
namespace ebcdic_dk_no_a {
  #include "ccs/ebcdic-dk-no-a.c"
  #undef NBITS
  }
namespace ebcdic_dk_no {
  #include "ccs/ebcdic-dk-no.c"
  #undef NBITS
  }
namespace ebcdic_es_a {
  #include "ccs/ebcdic-es-a.c"
  #undef NBITS
  }
namespace ebcdic_es {
  #include "ccs/ebcdic-es.c"
  #undef NBITS
  }
namespace ebcdic_es_s {
  #include "ccs/ebcdic-es-s.c"
  #undef NBITS
  }
namespace ebcdic_fi_se_a {
  #include "ccs/ebcdic-fi-se-a.c"
  #undef NBITS
  }
namespace ebcdic_fi_se {
  #include "ccs/ebcdic-fi-se.c"
  #undef NBITS
  }
namespace ebcdic_fr {
  #include "ccs/ebcdic-fr.c"
  #undef NBITS
  }
namespace ebcdic_it {
  #include "ccs/ebcdic-it.c"
  #undef NBITS
  }
namespace ebcdic_pt {
  #include "ccs/ebcdic-pt.c"
  #undef NBITS
  }
namespace ebcdic_uk {
  #include "ccs/ebcdic-uk.c"
  #undef NBITS
  }
namespace ebcdic_us {
  #include "ccs/ebcdic-us.c"
  #undef NBITS
  }
namespace gb12345 {
  #include "ccs/gb12345.c"
  #undef NBITS
  }
namespace gb_2312_80 {
  #include "ccs/gb_2312-80.c"
  #undef NBITS
  }
namespace hp_roman8 {
  #include "ccs/hp-roman8.c"
  #undef NBITS
  }
namespace iso646_dk {
  #include "ccs/iso646-dk.c"
  #undef NBITS
  }
namespace iso646_kr {
  #include "ccs/iso646-kr.c"
  #undef NBITS
  }
namespace iso_8859_10 {
  #include "ccs/iso-8859-10.c"
  #undef NBITS
  }
namespace iso_8859_13 {
  #include "ccs/iso-8859-13.c"
  #undef NBITS
  }
namespace iso_8859_14 {
  #include "ccs/iso-8859-14.c"
  #undef NBITS
  }
namespace iso_8859_15 {
  #include "ccs/iso-8859-15.c"
  #undef NBITS
  }
namespace iso_8859_1 {
  #include "ccs/iso-8859-1.c"
  #undef NBITS
  }
namespace iso_8859_2 {
  #include "ccs/iso-8859-2.c"
  #undef NBITS
  }
namespace iso_8859_3 {
  #include "ccs/iso-8859-3.c"
  #undef NBITS
  }
namespace iso_8859_4 {
  #include "ccs/iso-8859-4.c"
  #undef NBITS
  }
namespace iso_8859_5 {
  #include "ccs/iso-8859-5.c"
  #undef NBITS
  }
namespace iso_8859_6 {
  #include "ccs/iso-8859-6.c"
  #undef NBITS
  }
namespace iso_8859_7 {
  #include "ccs/iso-8859-7.c"
  #undef NBITS
  }
namespace iso_8859_8 {
  #include "ccs/iso-8859-8.c"
  #undef NBITS
  }
namespace iso_8859_9 {
  #include "ccs/iso-8859-9.c"
  #undef NBITS
  }
namespace iso_ir_102 {
  #include "ccs/iso-ir-102.c"
  #undef NBITS
  }
namespace iso_ir_103 {
  #include "ccs/iso-ir-103.c"
  #undef NBITS
  }
namespace iso_ir_10 {
  #include "ccs/iso-ir-10.c"
  #undef NBITS
  }
namespace iso_ir_111 {
  #include "ccs/iso-ir-111.c"
  #undef NBITS
  }
namespace iso_ir_11 {
  #include "ccs/iso-ir-11.c"
  #undef NBITS
  }
namespace iso_ir_121 {
  #include "ccs/iso-ir-121.c"
  #undef NBITS
  }
namespace iso_ir_122 {
  #include "ccs/iso-ir-122.c"
  #undef NBITS
  }
namespace iso_ir_123 {
  #include "ccs/iso-ir-123.c"
  #undef NBITS
  }
namespace iso_ir_128 {
  #include "ccs/iso-ir-128.c"
  #undef NBITS
  }
namespace iso_ir_139 {
  #include "ccs/iso-ir-139.c"
  #undef NBITS
  }
namespace iso_ir_13 {
  #include "ccs/iso-ir-13.c"
  #undef NBITS
  }
namespace iso_ir_141 {
  #include "ccs/iso-ir-141.c"
  #undef NBITS
  }
namespace iso_ir_142 {
  #include "ccs/iso-ir-142.c"
  #undef NBITS
  }
namespace iso_ir_143 {
  #include "ccs/iso-ir-143.c"
  #undef NBITS
  }
namespace iso_ir_146 {
  #include "ccs/iso-ir-146.c"
  #undef NBITS
  }
namespace iso_ir_147 {
  #include "ccs/iso-ir-147.c"
  #undef NBITS
  }
namespace iso_ir_14 {
  #include "ccs/iso-ir-14.c"
  #undef NBITS
  }
namespace iso_ir_150 {
  #include "ccs/iso-ir-150.c"
  #undef NBITS
  }
namespace iso_ir_151 {
  #include "ccs/iso-ir-151.c"
  #undef NBITS
  }
namespace iso_ir_152 {
  #include "ccs/iso-ir-152.c"
  #undef NBITS
  }
namespace iso_ir_153 {
  #include "ccs/iso-ir-153.c"
  #undef NBITS
  }
namespace iso_ir_154 {
  #include "ccs/iso-ir-154.c"
  #undef NBITS
  }
namespace iso_ir_155 {
  #include "ccs/iso-ir-155.c"
  #undef NBITS
  }
namespace iso_ir_158 {
  #include "ccs/iso-ir-158.c"
  #undef NBITS
  }
namespace iso_ir_15 {
  #include "ccs/iso-ir-15.c"
  #undef NBITS
  }
namespace iso_ir_16 {
  #include "ccs/iso-ir-16.c"
  #undef NBITS
  }
namespace iso_ir_17 {
  #include "ccs/iso-ir-17.c"
  #undef NBITS
}
namespace iso_ir_18 {
  #include "ccs/iso-ir-18.c"
  #undef NBITS
  }
namespace iso_ir_19 {
  #include "ccs/iso-ir-19.c"
  #undef NBITS
  }
namespace iso_ir_21 {
  #include "ccs/iso-ir-21.c"
  #undef NBITS
  }
namespace iso_ir_25 {
  #include "ccs/iso-ir-25.c"
  #undef NBITS
  }
namespace iso_ir_27 {
  #include "ccs/iso-ir-27.c"
  #undef NBITS
  }
namespace iso_ir_2 {
  #include "ccs/iso-ir-2.c"
  #undef NBITS
  }
namespace iso_ir_37 {
  #include "ccs/iso-ir-37.c"
  #undef NBITS
  }
namespace iso_ir_47 {
  #include "ccs/iso-ir-47.c"
  #undef NBITS
  }
namespace iso_ir_49 {
  #include "ccs/iso-ir-49.c"
  #undef NBITS
  }
namespace iso_ir_4 {
  #include "ccs/iso-ir-4.c"
  #undef NBITS
  }
namespace iso_ir_50 {
  #include "ccs/iso-ir-50.c"
  #undef NBITS
  }
namespace iso_ir_51 {
  #include "ccs/iso-ir-51.c"
  #undef NBITS
  }
namespace iso_ir_54 {
  #include "ccs/iso-ir-54.c"
  #undef NBITS
  }
namespace iso_ir_55 {
  #include "ccs/iso-ir-55.c"
  #undef NBITS
  }
namespace iso_ir_57 {
  #include "ccs/iso-ir-57.c"
  #undef NBITS
  }
namespace iso_ir_60 {
  #include "ccs/iso-ir-60.c"
  #undef NBITS
  }
namespace iso_ir_61 {
  #include "ccs/iso-ir-61.c"
  #undef NBITS
  }
namespace iso_ir_69 {
  #include "ccs/iso-ir-69.c"
  #undef NBITS
  }
namespace iso_ir_70 {
  #include "ccs/iso-ir-70.c"
  #undef NBITS
  }
namespace iso_ir_8_1 {
  #include "ccs/iso-ir-8-1.c"
  #undef NBITS
  }
namespace iso_ir_8_2 {
  #include "ccs/iso-ir-8-2.c"
  #undef NBITS
  }
namespace iso_ir_84 {
  #include "ccs/iso-ir-84.c"
  #undef NBITS
  }
namespace iso_ir_85 {
  #include "ccs/iso-ir-85.c"
  #undef NBITS
  }
namespace iso_ir_86 {
  #include "ccs/iso-ir-86.c"
  #undef NBITS
  }
namespace iso_ir_88 {
  #include "ccs/iso-ir-88.c"
  #undef NBITS
  }
namespace iso_ir_89 {
  #include "ccs/iso-ir-89.c"
  #undef NBITS
  }
namespace iso_ir_90 {
  #include "ccs/iso-ir-90.c"
  #undef NBITS
  }
namespace iso_ir_9_1 {
  #include "ccs/iso-ir-9-1.c"
  #undef NBITS
  }
namespace iso_ir_91 {
  #include "ccs/iso-ir-91.c"
  #undef NBITS
  }
namespace iso_ir_9_2 {
  #include "ccs/iso-ir-9-2.c"
  #undef NBITS
  }
namespace iso_ir_92 {
  #include "ccs/iso-ir-92.c"
  #undef NBITS
  }
namespace iso_ir_93 {
  #include "ccs/iso-ir-93.c"
  #undef NBITS
  }
namespace iso_ir_94 {
  #include "ccs/iso-ir-94.c"
  #undef NBITS
  }
namespace iso_ir_95 {
  #include "ccs/iso-ir-95.c"
  #undef NBITS
  }
namespace iso_ir_96 {
  #include "ccs/iso-ir-96.c"
  #undef NBITS
  }
namespace iso_ir_98 {
  #include "ccs/iso-ir-98.c"
  #undef NBITS
  }
namespace iso_ir_99 {
  #include "ccs/iso-ir-99.c"
  #undef NBITS
  }
namespace jis_x0201 {
  #include "ccs/jis_x0201.c"
  #undef NBITS
  }
namespace jis_x0208_1983 {
  #include "ccs/jis_x0208-1983.c"
  #undef NBITS
  }
namespace jis_x0212_1990 {
  #include "ccs/jis_x0212-1990.c"
  #undef NBITS
  }
namespace johab {
  #include "ccs/johab.c"
  #undef NBITS
  }
namespace koi8_r {
  #include "ccs/koi8-r.c"
  #undef NBITS
  }
namespace koi8_ru {
  #include "ccs/koi8-ru.c"
  #undef NBITS
  }
namespace koi8_u {
  #include "ccs/koi8-u.c"
  #undef NBITS
  }
namespace ksx1001 {
  #include "ccs/ksx1001.c"
  #undef NBITS
  }
namespace mac_ce {
  #include "ccs/mac-ce.c"
  #undef NBITS
  }
namespace mac_croatian {
  #include "ccs/mac-croatian.c"
  #undef NBITS
  }
namespace mac_cyrillic {
  #include "ccs/mac-cyrillic.c"
  #undef NBITS
  }
namespace mac_dingbats {
  #include "ccs/mac-dingbats.c"
  #undef NBITS
  }
namespace mac_greek {
  #include "ccs/mac-greek.c"
  #undef NBITS
  }
namespace mac_iceland {
  #include "ccs/mac-iceland.c"
  #undef NBITS
  }
namespace macintosh {
  #include "ccs/macintosh.c"
  #undef NBITS
  }
namespace mac_japan {
  #include "ccs/mac-japan.c"
  #undef NBITS
  }
namespace mac_roman {
  #include "ccs/mac-roman.c"
  #undef NBITS
  }
namespace mac_romania {
  #include "ccs/mac-romania.c"
  #undef NBITS
  }
namespace mac_thai {
  #include "ccs/mac-thai.c"
  #undef NBITS
  }
namespace mac_turkish {
  #include "ccs/mac-turkish.c"
  #undef NBITS
  }
namespace mac_ukraine {
  #include "ccs/mac-ukraine.c"
  #undef NBITS
  }
namespace osd_ebcdic_df04_15 {
  #include "ccs/osd_ebcdic_df04_15.c"
  #undef NBITS
  }
namespace osd_ebcdic_df04_1 {
  #include "ccs/osd_ebcdic_df04_1.c"
  #undef NBITS
  }
namespace shift_jis {
  #include "ccs/shift_jis.c"
  #undef NBITS
  }
namespace us_ascii {
  #include "ccs/us-ascii.c"
  #undef NBITS
  }
namespace windows_1250 {
  #include "ccs/windows-1250.c"
  #undef NBITS
  }
namespace windows_1251 {
  #include "ccs/windows-1251.c"
  #undef NBITS
  }
namespace windows_1252 {
  #include "ccs/windows-1252.c"
  #undef NBITS
  }
namespace windows_1253 {
  #include "ccs/windows-1253.c"
  #undef NBITS
  }
namespace windows_1254 {
  #include "ccs/windows-1254.c"
  #undef NBITS
  }
namespace windows_1255 {
  #include "ccs/windows-1255.c"
  #undef NBITS
  }
namespace windows_1256 {
  #include "ccs/windows-1256.c"
  #undef NBITS
  }
namespace windows_1257 {
  #include "ccs/windows-1257.c"
  #undef NBITS
  }
namespace windows_1258 {
  #include "ccs/windows-1258.c"
  #undef NBITS
  }
namespace euc_jp {
  #include "ces/euc-jp.c"
  #undef NBITS
  }
namespace euc_kr {
  #include "ces/euc-kr.c"
  #undef NBITS
  }
namespace euc_tw {
  #include "ces/euc-tw.c"
  #undef NBITS
  }
namespace gb2312 {
  #include "ces/gb2312.c"
  #undef NBITS
  }
namespace iso_10646_ucs_2 {
  #include "ces/iso-10646-ucs-2.c"
  #undef NBITS
  }
namespace iso_10646_ucs_4 {
  #include "ces/iso-10646-ucs-4.c"
  #undef NBITS
  }
namespace iso_2022_cn {
  #include "ces/iso-2022-cn.c"
  #undef NBITS
  }
namespace iso_2022_jp_2 {
  #include "ces/iso-2022-jp-2.c"
  #undef NBITS
  }
namespace iso_2022_jp {
  #include "ces/iso-2022-jp.c"
  #undef NBITS
  }
namespace iso_2022_kr {
  #include "ces/iso-2022-kr.c"
  #undef NBITS
  }
namespace _tbl_simple {
  #include "ces/_tbl_simple.c"
  #undef NBITS
  }
#if 0
namespace ucs2_internal {
  #include "ces/ucs2-internal.c"
  #undef NBITS
  }
namespace ucs4_internal {
  #include "ces/ucs4-internal.c"
  #undef NBITS
  }
namespace unicode_1_1_utf_7 {
  #include "ces/unicode-1-1-utf-7.c"
  #undef NBITS
  }
#endif
namespace utf_16 {
  #include "ces/utf-16.c"
  #undef NBITS
  }
namespace utf_8 {
  #include "ces/utf-8.c"
  #undef NBITS
  }
namespace iconv {
  apr_status_t iconv_getpath(char *buf, const char *name, apr_pool_t *ctx)
  {
    strcpy(buf, name);
    return APR_SUCCESS;
  }

#define LOCAL_MODULE(modname, ns) if (strcmp(name, modname) == 0) { *dpp = &ns::iconv_module; stat = 0; } else
#define LAST_LOCAL_MODULE(modname, ns) if (strcmp(name, modname) == 0) { *dpp = &ns::iconv_module;  stat = 0; }

  int iconv_dlopen(const char *name,
      const char *symbol,
      void **hpp,
      void **dpp,
      apr_pool_t *ctx) {
      int stat = EINVAL;
      switch(name[0]) {
        case 'a':
        LOCAL_MODULE("adobe-stdenc", adobe_stdenc)
        LOCAL_MODULE("adobe-symbol", adobe_symbol)
        LAST_LOCAL_MODULE("adobe-zdingbats", adobe_zdingbats)
        break;

        case 'b':
        LAST_LOCAL_MODULE("big5", big5)
        break;

        case 'c':
        LOCAL_MODULE("cns11643-plane14", cns11643_plane14)
        LOCAL_MODULE("cns11643-plane1", cns11643_plane1)
        LOCAL_MODULE("cns11643-plane2", cns11643_plane2)
        LOCAL_MODULE("cp037", cp037)
        LOCAL_MODULE("cp038", cp038)
        LOCAL_MODULE("cp10000", cp10000)
        LOCAL_MODULE("cp10006", cp10006)
        LOCAL_MODULE("cp10007", cp10007)
        LOCAL_MODULE("cp10029", cp10029)
        LOCAL_MODULE("cp1006", cp1006)
        LOCAL_MODULE("cp10079", cp10079)
        LOCAL_MODULE("cp10081", cp10081)
        LOCAL_MODULE("cp1026", cp1026)
        LOCAL_MODULE("cp273", cp273)
        LOCAL_MODULE("cp274", cp274)
        LOCAL_MODULE("cp275", cp275)
        LOCAL_MODULE("cp277", cp277)
        LOCAL_MODULE("cp278", cp278)
        LOCAL_MODULE("cp280", cp280)
        LOCAL_MODULE("cp281", cp281)
        LOCAL_MODULE("cp284", cp284)
        LOCAL_MODULE("cp285", cp285)
        LOCAL_MODULE("cp290", cp290)
        LOCAL_MODULE("cp297", cp297)
        LOCAL_MODULE("cp420", cp420)
        LOCAL_MODULE("cp423", cp423)
        LOCAL_MODULE("cp424", cp424)
        LOCAL_MODULE("cp437", cp437)
        LOCAL_MODULE("cp500", cp500)
        LOCAL_MODULE("cp737", cp737)
        LOCAL_MODULE("cp775", cp775)
        LOCAL_MODULE("cp850", cp850)
        LOCAL_MODULE("cp851", cp851)
        LOCAL_MODULE("cp852", cp852)
        LOCAL_MODULE("cp855", cp855)
        LOCAL_MODULE("cp856", cp856)
        LOCAL_MODULE("cp857", cp857)
        LOCAL_MODULE("cp860", cp860)
        LOCAL_MODULE("cp861", cp861)
        LOCAL_MODULE("cp862", cp862)
        LOCAL_MODULE("cp863", cp863)
        LOCAL_MODULE("cp864", cp864)
        LOCAL_MODULE("cp865", cp865)
        LOCAL_MODULE("cp866", cp866)
        LOCAL_MODULE("cp868", cp868)
        LOCAL_MODULE("cp869", cp869)
        LOCAL_MODULE("cp870", cp870)
        LOCAL_MODULE("cp871", cp871)
        LOCAL_MODULE("cp874", cp874)
        LOCAL_MODULE("cp875", cp875)
        LOCAL_MODULE("cp880", cp880)
        LOCAL_MODULE("cp891", cp891)
        LOCAL_MODULE("cp903", cp903)
        LOCAL_MODULE("cp904", cp904)
        LOCAL_MODULE("cp905", cp905)
        LOCAL_MODULE("cp918", cp918)
        LOCAL_MODULE("cp932", cp932)
        LOCAL_MODULE("cp936", cp936)
        LOCAL_MODULE("cp949", cp949)
        LAST_LOCAL_MODULE("cp950", cp950)
        break;

        case 'd':
        LAST_LOCAL_MODULE("dec-mcs", dec_mcs)
        break;

        case 'e':
        LOCAL_MODULE("ebcdic-at-de-a", ebcdic_at_de_a)
        LOCAL_MODULE("ebcdic-at-de", ebcdic_at_de)
        LOCAL_MODULE("ebcdic-ca-fr", ebcdic_ca_fr)
        LOCAL_MODULE("ebcdic-dk-no-a", ebcdic_dk_no_a)
        LOCAL_MODULE("ebcdic-dk-no", ebcdic_dk_no)
        LOCAL_MODULE("ebcdic-es-a", ebcdic_es_a)
        LOCAL_MODULE("ebcdic-es", ebcdic_es)
        LOCAL_MODULE("ebcdic-es-s", ebcdic_es_s)
        LOCAL_MODULE("ebcdic-fi-se-a", ebcdic_fi_se_a)
        LOCAL_MODULE("ebcdic-fi-se", ebcdic_fi_se)
        LOCAL_MODULE("ebcdic-fr", ebcdic_fr)
        LOCAL_MODULE("ebcdic-it", ebcdic_it)
        LOCAL_MODULE("ebcdic-pt", ebcdic_pt)
        LOCAL_MODULE("ebcdic-uk", ebcdic_uk)
        LOCAL_MODULE("ebcdic-us", ebcdic_us)
        LOCAL_MODULE("euc-jp", euc_jp)
        LOCAL_MODULE("euc-kr", euc_kr)
        LAST_LOCAL_MODULE("euc-tw", euc_tw)
        break;

        case 'g':
        LOCAL_MODULE("gb2312", gb2312)
        LOCAL_MODULE("gb12345", gb12345)
        LAST_LOCAL_MODULE("gb_2312-80", gb_2312_80)
        break;

        case 'h':
        LAST_LOCAL_MODULE("hp-roman8", hp_roman8)
        break;

        case 'i':
        LOCAL_MODULE("iso646-dk", iso646_dk)
        LOCAL_MODULE("iso646-kr", iso646_kr)
        LOCAL_MODULE("iso-10646-ucs-2", iso_10646_ucs_2)
        LOCAL_MODULE("iso-10646-ucs-4", iso_10646_ucs_4)
        LOCAL_MODULE("iso-2022-cn", iso_2022_cn)
        LOCAL_MODULE("iso-2022-jp-2", iso_2022_jp_2)
        LOCAL_MODULE("iso-2022-jp", iso_2022_jp)
        LOCAL_MODULE("iso-2022-kr", iso_2022_kr)
        LOCAL_MODULE("iso-8859-10", iso_8859_10)
        LOCAL_MODULE("iso-8859-10", iso_8859_10)
        LOCAL_MODULE("iso-8859-13", iso_8859_13)
        LOCAL_MODULE("iso-8859-14", iso_8859_14)
        LOCAL_MODULE("iso-8859-15", iso_8859_15)
        LOCAL_MODULE("iso-8859-1", iso_8859_1)
        LOCAL_MODULE("iso-8859-2", iso_8859_2)
        LOCAL_MODULE("iso-8859-3", iso_8859_3)
        LOCAL_MODULE("iso-8859-4", iso_8859_4)
        LOCAL_MODULE("iso-8859-5", iso_8859_5)
        LOCAL_MODULE("iso-8859-6", iso_8859_6)
        LOCAL_MODULE("iso-8859-7", iso_8859_7)
        LOCAL_MODULE("iso-8859-8", iso_8859_8)
        LOCAL_MODULE("iso-8859-9", iso_8859_9)
        LOCAL_MODULE("iso-ir-102", iso_ir_102)
        LOCAL_MODULE("iso-ir-103", iso_ir_103)
        LOCAL_MODULE("iso-ir-10", iso_ir_10)
        LOCAL_MODULE("iso-ir-111", iso_ir_111)
        LOCAL_MODULE("iso-ir-11", iso_ir_11)
        LOCAL_MODULE("iso-ir-121", iso_ir_121)
        LOCAL_MODULE("iso-ir-122", iso_ir_122)
        LOCAL_MODULE("iso-ir-123", iso_ir_123)
        LOCAL_MODULE("iso-ir-128", iso_ir_128)
        LOCAL_MODULE("iso-ir-139", iso_ir_139)
        LOCAL_MODULE("iso-ir-13", iso_ir_13)
        LOCAL_MODULE("iso-ir-141", iso_ir_141)
        LOCAL_MODULE("iso-ir-142", iso_ir_142)
        LOCAL_MODULE("iso-ir-143", iso_ir_143)
        LOCAL_MODULE("iso-ir-146", iso_ir_146)
        LOCAL_MODULE("iso-ir-147", iso_ir_147)
        LOCAL_MODULE("iso-ir-14", iso_ir_14)
        LOCAL_MODULE("iso-ir-150", iso_ir_150)
        LOCAL_MODULE("iso-ir-151", iso_ir_151)
        LOCAL_MODULE("iso-ir-152", iso_ir_152)
        LOCAL_MODULE("iso-ir-153", iso_ir_153)
        LOCAL_MODULE("iso-ir-154", iso_ir_154)
        LOCAL_MODULE("iso-ir-155", iso_ir_155)
        LOCAL_MODULE("iso-ir-158", iso_ir_158)
        LOCAL_MODULE("iso-ir-15", iso_ir_15)
        LOCAL_MODULE("iso-ir-16", iso_ir_16)
        LOCAL_MODULE("iso-ir-17", iso_ir_17)
        LOCAL_MODULE("iso-ir-18", iso_ir_18)
        LOCAL_MODULE("iso-ir-19", iso_ir_19)
        LOCAL_MODULE("iso-ir-21", iso_ir_21)
        LOCAL_MODULE("iso-ir-25", iso_ir_25)
        LOCAL_MODULE("iso-ir-27", iso_ir_27)
        LOCAL_MODULE("iso-ir-2", iso_ir_2)
        LOCAL_MODULE("iso-ir-37", iso_ir_37)
        LOCAL_MODULE("iso-ir-47", iso_ir_47)
        LOCAL_MODULE("iso-ir-49", iso_ir_49)
        LOCAL_MODULE("iso-ir-4", iso_ir_4)
        LOCAL_MODULE("iso-ir-50", iso_ir_50)
        LOCAL_MODULE("iso-ir-51", iso_ir_51)
        LOCAL_MODULE("iso-ir-54", iso_ir_54)
        LOCAL_MODULE("iso-ir-55", iso_ir_55)
        LOCAL_MODULE("iso-ir-57", iso_ir_57)
        LOCAL_MODULE("iso-ir-60", iso_ir_60)
        LOCAL_MODULE("iso-ir-61", iso_ir_61)
        LOCAL_MODULE("iso-ir-69", iso_ir_69)
        LOCAL_MODULE("iso-ir-70", iso_ir_70)
        LOCAL_MODULE("iso-ir-8-1", iso_ir_8_1)
        LOCAL_MODULE("iso-ir-8-2", iso_ir_8_2)
        LOCAL_MODULE("iso-ir-84", iso_ir_84)
        LOCAL_MODULE("iso-ir-85", iso_ir_85)
        LOCAL_MODULE("iso-ir-86", iso_ir_86)
        LOCAL_MODULE("iso-ir-88", iso_ir_88)
        LOCAL_MODULE("iso-ir-89", iso_ir_89)
        LOCAL_MODULE("iso-ir-90", iso_ir_90)
        LOCAL_MODULE("iso-ir-9-1", iso_ir_9_1)
        LOCAL_MODULE("iso-ir-91", iso_ir_91)
        LOCAL_MODULE("iso-ir-9-2", iso_ir_9_2)
        LOCAL_MODULE("iso-ir-92", iso_ir_92)
        LOCAL_MODULE("iso-ir-93", iso_ir_93)
        LOCAL_MODULE("iso-ir-94", iso_ir_94)
        LOCAL_MODULE("iso-ir-95", iso_ir_95)
        LOCAL_MODULE("iso-ir-96", iso_ir_96)
        LOCAL_MODULE("iso-ir-98", iso_ir_98)
        LAST_LOCAL_MODULE("iso-ir-99", iso_ir_99)
        break;

        case 'j':
        LOCAL_MODULE("jis_x0201", jis_x0201)
        LOCAL_MODULE("jis_x0208-1983", jis_x0208_1983)
        LOCAL_MODULE("jis_x0212-1990", jis_x0212_1990)
        LAST_LOCAL_MODULE("johab", johab)
        break;

        case 'k':
        LOCAL_MODULE("koi8-r", koi8_r)
        LOCAL_MODULE("koi8-ru", koi8_ru)
        LOCAL_MODULE("koi8-u", koi8_u)
        LAST_LOCAL_MODULE("ksx1001", ksx1001)
        break;

        case 'm':
        LOCAL_MODULE("mac-ce", mac_ce)
        LOCAL_MODULE("mac-croatian", mac_croatian)
        LOCAL_MODULE("mac-cyrillic", mac_cyrillic)
        LOCAL_MODULE("mac-dingbats", mac_dingbats)
        LOCAL_MODULE("mac-greek", mac_greek)
        LOCAL_MODULE("mac-iceland", mac_iceland)
        LOCAL_MODULE("macintosh", macintosh)
        LOCAL_MODULE("mac-japan", mac_japan)
        LOCAL_MODULE("mac-roman", mac_roman)
        LOCAL_MODULE("mac-romania", mac_romania)
        LOCAL_MODULE("mac-thai", mac_thai)
        LOCAL_MODULE("mac-turkish", mac_turkish)
        LAST_LOCAL_MODULE("mac-ukraine", mac_ukraine)
        break;

        case 'o':
        LOCAL_MODULE("osd_ebcdic_df04_15", osd_ebcdic_df04_15)
        LAST_LOCAL_MODULE("osd_ebcdic_df04_1", osd_ebcdic_df04_1)
        break;

        case 's':
        LAST_LOCAL_MODULE("shift_jis", shift_jis)
        break;

        case 'u':
        LOCAL_MODULE("us-ascii", us_ascii)
        LOCAL_MODULE("utf-16", utf_16)
        LAST_LOCAL_MODULE("utf-8", utf_8)
        break;

        case 'w':
        LOCAL_MODULE("windows-1250", windows_1250)
        LOCAL_MODULE("windows-1251", windows_1251)
        LOCAL_MODULE("windows-1252", windows_1252)
        LOCAL_MODULE("windows-1253", windows_1253)
        LOCAL_MODULE("windows-1254", windows_1254)
        LOCAL_MODULE("windows-1255", windows_1255)
        LOCAL_MODULE("windows-1256", windows_1256)
        LOCAL_MODULE("windows-1257", windows_1257)
        LAST_LOCAL_MODULE("windows-1258", windows_1258)
        break;
      }
      return stat;
    }
  }
}

using namespace log4cxx::iconv;

API_DECLARE_NONSTD(int)
apr_iconv_mod_load(const char *modname, int modtype, const void *args,
        struct iconv_module **modpp, apr_pool_t *ctx)
{
        struct iconv_module_desc *mdesc;
        struct iconv_module *mod, *depmod;
        const struct iconv_module_depend *depend;
        char buffer[APR_PATH_MAX];
        void *handle;
        int error;

        if (iconv_getpath(buffer, modname, ctx) != 0)
                return EINVAL;

        error = iconv_dlopen(buffer, "iconv_module", &handle, (void**)&mdesc, ctx);
        if (error)
                return error;
        mod = (iconv_module*) malloc(sizeof(*mod));
        if (mod == NULL) {
                return ENOMEM;
        }
        memset(mod, 0, sizeof(*mod));
        mod->im_handle = handle;
        mod->im_desc = mdesc;
        mod->im_args = args;
        depend = mdesc->imd_depend;
        error = ICONV_MOD_DYN_LOAD(mod,ctx);
        if (error)
                goto bad;
        error = ICONV_MOD_LOAD(mod,ctx);
        if (error)
                goto bad;
        mod->im_flags |= ICMODF_LOADED;
        *modpp = mod;
        return 0;
bad:
        apr_iconv_mod_unload(mod,ctx);
        return error;
}

API_DECLARE_NONSTD(int)
apr_iconv_mod_unload(struct iconv_module *mod, apr_pool_t *ctx)
{
        if (mod == NULL)
                return -1;
        free(mod);
        return 0;
}

API_DECLARE_NONSTD(int)
apr_iconv_mod_noevent(struct iconv_module *mod, int event, apr_pool_t *ctx)
{
        switch (event) {
            case ICMODEV_LOAD:
            case ICMODEV_UNLOAD:
            case ICMODEV_DYN_LOAD:
            case ICMODEV_DYN_UNLOAD:
                break;
            default:
                return APR_EINVAL;
        }
        return 0;
}
