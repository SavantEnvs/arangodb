// Fuzzes ArangoDB's ISO-8601 date/time and duration parsers and the date formatter.
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <regex>
#include <string>
#include <string_view>

#include "Basics/datetime.h"

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  std::string_view in(reinterpret_cast<char const*>(data), size);
  arangodb::tp_sys_clock_ms tp;
  if (arangodb::basics::parseDateTime(in, tp)) {
    (void)arangodb::basics::formatDate("%yyyy-%mm-%dd %hh:%ii:%ss.%fff %z %w %q", tp);
    (void)arangodb::basics::formatDate("%a %A %b %B %c %d %e %F %g %H %I %j %m %M %p %S %u %U %y %Y", tp);
  }
  arangodb::basics::ParsedDuration d;
  (void)arangodb::basics::parseIsoDuration(in, d);
  if (size > 0) {
    // the first byte picks the format string, the rest is the format itself
    (void)arangodb::basics::formatDate(std::string(in.substr(1)), arangodb::tp_sys_clock_ms{std::chrono::milliseconds(static_cast<int64_t>(data[0]) * 86400000LL * 37)});
  }
  return 0;
}
