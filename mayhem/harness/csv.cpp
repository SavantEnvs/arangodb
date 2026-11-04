// Fuzzes ArangoDB's streaming CSV parser (used by arangoimport).
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include "Basics/csv.h"

static void onBegin(TRI_csv_parser_t*, size_t) {}
static void onField(TRI_csv_parser_t* p, char const* field, size_t len,
                    size_t, size_t, bool) {
  *static_cast<size_t*>(p->_data) += len;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  if (size < 3) {
    return 0;
  }
  size_t total = 0;
  TRI_csv_parser_t parser;
  TRI_InitCsvParser(&parser, onBegin, onField, onField, &total);
  TRI_SetSeparatorCsvParser(&parser, static_cast<char>(data[0]));
  TRI_SetQuoteCsvParser(&parser, static_cast<char>(data[1]), (data[2] & 1) != 0);
  if (data[2] & 2) {
    TRI_UseBackslashCsvParser(&parser, true);
  }
  data += 3;
  size -= 3;
  // feed in two chunks so the buffer-resume logic is exercised
  size_t cut = size / 3;
  std::string a(reinterpret_cast<char const*>(data), cut);
  std::string b(reinterpret_cast<char const*>(data) + cut, size - cut);
  TRI_ParseCsvString(&parser, a.data(), a.size());
  TRI_ParseCsvString(&parser, b.data(), b.size());
  TRI_DestroyCsvParser(&parser);
  return 0;
}
