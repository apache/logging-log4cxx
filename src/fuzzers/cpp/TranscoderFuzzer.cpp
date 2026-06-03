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

//
// Fuzzer for the charset transcoding layer
// (Transcoder, CharsetDecoder, CharsetEncoder).
//
// This is the code that turns untrusted external bytes into the internal
// LogString and back out again for every appender.  It has historically been
// the source of several memory-safety and correctness defects in the decode
// boundary, for example:
//
//   * reject invalid UTF-8 lead bytes F8..FF in Transcoder::decode (#699)
//   * UTF-8 recovery loop end-of-input handling                    (#695)
//   * reject UTF-16 surrogate-half encodings in UTF-8             (#669)
//   * nullptr pointer arithmetic in charset decoder              (#670)
//   * UTF-8 decoder rejecting valid U+0800 three-byte sequence   (#664)
//   * ISO Latin-1 decoder sign extension                         (#660)
//   * UTF-16 supplementary character encoding                    (#659)
//   * infinite loop in MbstowcsCharsetDecoder                    (#589)
//
// The harness drives that layer with arbitrary bytes under ASan and the
// integer-overflow sanitizer, and additionally checks two round-trip
// invariants that a substitution-collision / aliasing defect (the class of
// bug behind #699 and #669) would break.
//

#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/charsetdecoder.h>
#include <log4cxx/helpers/charsetencoder.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <exception>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

namespace
{
	const size_t MaximumByteCount = 1 << 16;

	// Abort so libFuzzer/ASan reports the violation with a saved reproducer.
	void requireInvariant(bool ok, const char* what)
	{
		if (!ok)
		{
			fprintf(stderr, "transcoder invariant violated: %s\n", what);
			abort();
		}
	}

	// Independent UTF-16 reference decoder used only by the oracle below.
	// Kept deliberately tiny and self-contained so that it cannot share a
	// defect with the Transcoder::encodeUTF16BE/LE functions it validates: it
	// reassembles the two big/little-endian bytes of each code unit and applies
	// the standard surrogate-pair formula, nothing more.
	unsigned int referenceDecodeUTF16(const char* raw, size_t n, bool bigEndian)
	{
		auto unit = [&](size_t i) -> unsigned int
		{
			unsigned char hi = (unsigned char) raw[bigEndian ? i : i + 1];
			unsigned char lo = (unsigned char) raw[bigEndian ? i + 1 : i];
			return (unsigned int) ((hi << 8) | lo);
		};

		if (n == 2)
			return unit(0);
		if (n == 4)
		{
			unsigned int hs = unit(0);
			unsigned int ls = unit(2);
			return (hs - 0xD800) * 0x400 + (ls - 0xDC00) + 0x10000;
		}
		return 0xFFFFFFFFu; // unexpected length -- not this oracle's concern
	}

	// Oracle: a Unicode scalar encoded to UTF-16BE/LE and decoded back through
	// the independent reference above must reproduce the scalar.  This is the
	// round trip that exercises *and checks* Transcoder::encodeUTF16BE/LE -- the
	// surrogate-pair byte encoders fixed in #659.  Those functions are reached
	// from UTF16BECharsetEncoder::encode, but the named-codec path discards the
	// bytes, leaving the encoders without a correctness oracle; this supplies
	// one.  A defect that mis-derives a surrogate byte (in bounds, no crash)
	// silently decodes to the wrong code point and trips this check.
	void checkUTF16RoundTrip(unsigned int sv)
	{
		char be[4] = { 0, 0, 0, 0 };
		ByteBuffer beBuf(be, sizeof be);
		Transcoder::encodeUTF16BE(sv, beBuf);
		requireInvariant(referenceDecodeUTF16(be, beBuf.position(), true) == sv,
			"UTF-16BE encode/decode round trip corrupted the code point");

		char le[4] = { 0, 0, 0, 0 };
		ByteBuffer leBuf(le, sizeof le);
		Transcoder::encodeUTF16LE(sv, leBuf);
		requireInvariant(referenceDecodeUTF16(le, leBuf.position(), false) == sv,
			"UTF-16LE encode/decode round trip corrupted the code point");
	}

	// Drive a decoder over every byte of `bytes`, mirroring the error-recovery
	// loop in Transcoder::decode so that a single invalid byte advances the
	// cursor instead of stalling it.  The defensive no-progress break guards
	// the harness against a hang if a decoder ever returns success without
	// consuming input (that condition is itself worth surfacing, but as a
	// finding rather than a fuzzer timeout).
	void exerciseDecoder(const CharsetDecoderPtr& decoder, const std::string& bytes)
	{
		if (!decoder || bytes.empty())
			return;

		LogString out;
		ByteBuffer buf(const_cast<char*>(bytes.data()), bytes.size());

		while (buf.remaining() > 0)
		{
			size_t before = buf.position();
			log4cxx_status_t stat = decoder->decode(buf, out);

			if (CharsetDecoder::isError(stat))
			{
				out.append(1, (logchar) Transcoder::LOSSCHAR);
				buf.increment_position(1);
			}
			else if (buf.position() == before)
			{
				break;
			}
		}

		decoder->decode(buf, out); // flush any pending state
	}

	// Drain an entire LogString through `encoder`, mirroring the loop in
	// Transcoder::encode (flip / consume / clear) and advancing past any
	// character the target charset cannot represent.
	void exerciseEncoder(const CharsetEncoderPtr& encoder, const LogString& in)
	{
		if (!encoder)
			return;

		char scratch[128];
		std::string sink;
		ByteBuffer out(scratch, sizeof scratch);
		LogString::const_iterator iter = in.begin();

		while (iter != in.end())
		{
			LogString::const_iterator before = iter;
			log4cxx_status_t stat = encoder->encode(in, iter, out);
			out.flip();
			sink.append(out.data(), out.limit());
			out.clear();

			if (CharsetEncoder::isError(stat))
			{
				if (iter != in.end())
					++iter; // skip the unrepresentable character
			}
			else if (iter == before)
			{
				break; // defensive: success without progress
			}
		}

		encoder->flush(out);
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	FuzzedDataProvider fdp(data, size);

	// Reserve a one-byte selector for the named charset exercised below, then
	// treat the remainder as the untrusted byte stream.
	const int charsetSel = fdp.ConsumeIntegralInRange<int>(0, 4);
	std::string bytes = fdp.ConsumeRandomLengthString(MaximumByteCount);

	// Path 1: decode in the configured default code page
	// (this is what every std::string -> LogString conversion uses).
	LogString viaDefault;
	Transcoder::decode(bytes, viaDefault);

	// Path 2: explicit UTF-8 decode through the hardened scalar decoder.
	// decodeUTF8 replaces every malformed sequence with LOSSCHAR, so the
	// result contains only well-formed Unicode scalar values.
	LogString sanitized;
	Transcoder::decodeUTF8(bytes, sanitized);

	// Invariant A: because `sanitized` is already well-formed, encoding it to
	// UTF-8 and decoding it again must reproduce it exactly.  A decode/encode
	// asymmetry -- e.g. a malformed input aliasing onto an in-range code point
	// inconsistently -- breaks this fixed point.
	std::string utf8;
	Transcoder::encodeUTF8(sanitized, utf8);
	LogString reSanitized;
	Transcoder::decodeUTF8(utf8, reSanitized);
	requireInvariant(sanitized == reSanitized,
		"decodeUTF8/encodeUTF8 round trip is not idempotent");

	// Path 3: default-charset encode of the sanitized string.
	std::string reencoded;
	Transcoder::encode(sanitized, reencoded);

	// Path 4: every named codec, driven over the raw fuzz bytes (decode) and
	// over the full Unicode range (encode -- exercises the unrepresentable
	// character / error-recovery branches of US-ASCII and ISO-8859-1).
	static const LogString charsetNames[] =
	{
		LOG4CXX_STR("US-ASCII"),
		LOG4CXX_STR("ISO-8859-1"),
		LOG4CXX_STR("UTF-8"),
		LOG4CXX_STR("UTF-16BE"),
		LOG4CXX_STR("UTF-16LE"),
	};
	const LogString& charset = charsetNames[charsetSel % 5];

	try
	{
		exerciseDecoder(CharsetDecoder::getDecoder(charset), bytes);
		exerciseEncoder(CharsetEncoder::getEncoder(charset), sanitized);
	}
	catch (const std::exception&)
	{
		// getDecoder/getEncoder throw IllegalArgumentException for an
		// unrecognised name; all names above are valid, but stay defensive.
	}

	// Path 6: UTF-16BE/LE byte-encoder round trip over every scalar decoded
	// from the input.  Unlike Path 4 (which discards the encoder's bytes), this
	// drives Transcoder::encodeUTF16BE/LE directly -- the exact #659 site -- with
	// real code points, including supplementary-plane scalars that form surrogate
	// pairs, and verifies each survives a decode.  Portable across LOG4CXX_CHAR
	// configurations because it reads scalars through the UTF-8 scalar decoder
	// rather than the platform wchar_t path.
	{
		std::string::const_iterator it = bytes.begin();
		while (it != bytes.end())
		{
			unsigned int sv = Transcoder::decode(bytes, it);
			if (sv == 0xFFFF)
			{
				++it; // mirror decodeUTF8's recovery advance on a bad sequence
				continue;
			}
			checkUTF16RoundTrip(sv);
		}
	}

#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR || defined(WIN32) || defined(_WIN32)
	// Path 5: wide round trip, covering the UTF-16 surrogate-pair handling
	// that produced #659.  `sanitized` holds no surrogate-range scalars, so
	// encoding to wchar_t and decoding back must be a fixed point.
	std::wstring wide;
	Transcoder::encode(sanitized, wide);
	LogString fromWide;
	Transcoder::decode(wide, fromWide);
	requireInvariant(sanitized == fromWide,
		"wchar_t encode/decode round trip is not idempotent");
#endif

	return 0;
}
