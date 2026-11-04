// Fuzzes HttpRequest URL / query-string / header / cookie parsing.
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <cstdlib>
#include <algorithm>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <velocypack/Builder.h>
#include <velocypack/Slice.h>

#include <sstream>
#include <iostream>
#include <fstream>
#include <regex>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <functional>
#include <variant>
#include <optional>
#define private public
#include "Rest/HttpRequest.h"
#undef private
#include "Rest/CommonDefines.h"

using arangodb::ConnectionInfo;
using arangodb::HttpRequest;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  if (size < 1) {
    return 0;
  }
  uint8_t sel = data[0];
  ++data;
  --size;
  // the parsers decode in place and expect a NUL-terminated mutable buffer
  std::vector<char> buf(data, data + size);
  buf.push_back('\0');
  ConnectionInfo ci;
  HttpRequest req(ci, 1);
  try {
    if (sel & 1) {
      req.parseHeader(buf.data(), size);
    } else if (sel & 2) {
      req.parseUrl(buf.data(), size);
    } else {
      req.parseCookies(buf.data(), size);
    }
    (void)req.fullUrl();
    (void)req.requestPath();
    (void)req.values();
    (void)req.arrayValues();
    (void)req.headers();
    (void)req.cookieValues();
  } catch (std::exception const&) {
  }
  return 0;
}
