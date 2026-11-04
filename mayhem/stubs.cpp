// Link-time support for the subset of lib/ that the harnesses compile: the full crash handler
// and the server version banner depend on RocksDB/V8, which are not built here.
#include <cstdio>
#include <cstdlib>
#include <ostream>

#include "CrashHandler/CrashHandler.h"
#include "Rest/Version.h"

namespace arangodb {
namespace crash_handler {
void CrashHandler::assertionFailure(char const* file, int line,
                                    char const* func, char const* context,
                                    char const* message) {
  std::fprintf(stderr, "ASSERT FAILED: %s:%d: %s: %s %s\n", file, line, func,
               context, message);
  std::abort();
}
}  // namespace crash_handler
namespace rest {
void Version::print(std::ostream&) {}
void Version::printJson(std::ostream&) {}
}  // namespace rest
}  // namespace arangodb
