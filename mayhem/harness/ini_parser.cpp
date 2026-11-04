// Fuzzes the arangod .conf (INI) parser against a small option set.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "ProgramOptions/IniFileParser.h"
#include "ProgramOptions/Parameters.h"
#include "ProgramOptions/ProgramOptions.h"

using namespace arangodb::options;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  std::string content(reinterpret_cast<char const*>(data), size);
  if (content.find("@include") != std::string::npos) {
    return 0;  // would read arbitrary files from the fuzz machine
  }
  ProgramOptions options("fuzz", "usage", "more", "/tmp/fuzz");
  std::string s;
  uint64_t u = 0;
  double d = 0;
  bool b = false;
  int32_t i = 0;
  std::vector<std::string> list;
  options.addSection("server", "server options");
  options.addOption("--server.name", "name", new StringParameter(&s));
  options.addOption("--server.threads", "threads", new UInt64Parameter(&u));
  options.addOption("--server.ratio", "ratio", new DoubleParameter(&d));
  options.addOption("--server.flag", "flag", new BooleanParameter(&b));
  options.addOption("--server.level", "level", new Int32Parameter(&i));
  options.addOption("--server.list", "list", new VectorParameter<StringParameter>(&list));
  options.addSection("log", "log options");
  options.addOption("--log.level", "level", new VectorParameter<StringParameter>(&list));
  options.addOption("--log.file", "file", new StringParameter(&s));
  IniFileParser parser(&options);
  (void)parser.parseContent("fuzz.conf", content, true);
  (void)options.processingResult().touched("server.name");
  return 0;
}
