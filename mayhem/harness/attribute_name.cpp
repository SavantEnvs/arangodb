// Fuzzes the attribute path parser ("a.b[*].c") and its inverse.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "Basics/AttributeNameParser.h"
#include "Basics/Exceptions.h"
#include "Basics/Result.h"

using namespace arangodb::basics;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  if (size < 1) {
    return 0;
  }
  bool expand = (data[0] & 1) != 0;
  std::string_view in(reinterpret_cast<char const*>(data) + 1, size - 1);
  std::vector<AttributeName> parsed;
  try {
    TRI_ParseAttributeString(in, parsed, expand);
    std::string back;
    TRI_AttributeNamesToString(parsed, back, true);
    std::vector<AttributeName> again;
    TRI_ParseAttributeString(back, again, expand);
    std::string back2;
    TRI_AttributeNamesToString(again, back2, true);
    if (back != back2) {
      __builtin_trap();
    }
  } catch (arangodb::basics::Exception const&) {
  }
  return 0;
}
