// Fuzzes ArangoDB's string helpers: URL/hex coding, number parsing, split/trim/replace, unicode escaping.
#include <cstddef>
#include <cstdint>
#include <string>
#include <exception>
#include <string_view>

#include "Basics/ResultT.h"
#include "Basics/StringUtils.h"

using namespace arangodb::basics;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  if (size < 1) {
    return 0;
  }
  uint8_t sel = data[0];
  std::string_view in(reinterpret_cast<char const*>(data) + 1, size - 1);
  std::string s(in);
  size_t half = in.size() / 2;
  // std::strings (s, sa, sb) keep every view NUL-terminated: several helpers read view.data() past size
  // (strlen, doubleDecimal's *ptr before its size check). Never hand them `in`, a view into the fuzzer buffer.
  std::string_view t(s);
  std::string sa(in.substr(0, half)), sb(in.substr(half));
  std::string_view a(sa), b(sb);

  try {
  switch (sel % 16) {
    case 0: {
      std::string d = StringUtils::urlDecode(in);
      std::string e = StringUtils::urlEncode(d);
      if (StringUtils::urlDecode(e) != d) {
        __builtin_trap();
      }
      (void)StringUtils::urlDecodePath(in);
      break;
    }
    case 1: {
      std::string h = StringUtils::encodeHex(in);
      if (StringUtils::decodeHex(h) != s) {
        __builtin_trap();
      }
      (void)StringUtils::decodeHex(in);
      break;
    }
    case 2:
      (void)StringUtils::int64(in);
      (void)StringUtils::uint64(in);
      (void)StringUtils::int32(in);
      (void)StringUtils::uint32(in);
      (void)StringUtils::try_uint64(in);
      (void)StringUtils::boolean(in);
      break;
    case 3:
      (void)StringUtils::doubleDecimal(t);
      (void)StringUtils::floatDecimal(t);
      break;
    case 4:
      (void)StringUtils::split(in, ',');
      (void)StringUtils::split(a, b);
      (void)StringUtils::split(in, std::string_view(";\n"));
      break;
    case 5:
      (void)StringUtils::trim(a, b);
      (void)StringUtils::lTrim(a, b);
      (void)StringUtils::rTrim(a, b);
      (void)StringUtils::replace(t, a, b);
      break;
    case 6:
      (void)StringUtils::escapeUnicode(in, true);
      (void)StringUtils::escapeUnicode(in, false);
      break;
    case 7:
      (void)StringUtils::soundex(in);
      (void)StringUtils::levenshteinDistance(a.data(), a.size(), b.data(), b.size());
      (void)StringUtils::characterCodes(in.data(), in.size());
      break;
    case 8:
      (void)StringUtils::escapeRegexParams(in);
      (void)StringUtils::correctPath(in);
      (void)StringUtils::encodeURIComponent(in);
      break;
    case 9:
      (void)StringUtils::wrap(in, 1 + (sel >> 4), b);
      (void)StringUtils::lFill(in, sel, ' ');
      (void)StringUtils::rFill(in, sel, '.');
      break;
    case 10:
      (void)StringUtils::tolower(in);
      (void)StringUtils::toupper(in);
      break;
    case 11:
      (void)StringUtils::formatSize(StringUtils::uint64(in));
      (void)StringUtils::itoa(StringUtils::int64(in));
      (void)StringUtils::ftoa(StringUtils::doubleDecimal(t));
      break;
    default:
      (void)StringUtils::concatT(a, b, a);
      (void)StringUtils::joinT(",", a, b);
      break;
  }
  } catch (std::exception const&) {  // e.g. ArangoException on invalid UTF-8 is documented behaviour
  }
  return 0;
}
