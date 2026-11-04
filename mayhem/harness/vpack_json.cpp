// Fuzzes the velocypack JSON parser, the JSON/pretty dumpers and the validator.
#include <cstddef>
#include <cstdint>
#include <string>

#include <velocypack/Builder.h>
#include <velocypack/Dumper.h>
#include <velocypack/Options.h>
#include <velocypack/Parser.h>
#include <velocypack/Slice.h>
#include <velocypack/Validator.h>
#include <velocypack/Collection.h>
#include <velocypack/Exception.h>
#include <velocypack/Sink.h>

using namespace arangodb::velocypack;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  if (size < 1) {
    return 0;
  }
  uint8_t flags = data[0];
  ++data;
  --size;

  Options options;
  options.validateUtf8Strings = (flags & 1) != 0;
  options.checkAttributeUniqueness = (flags & 2) != 0;
  options.buildUnindexedArrays = (flags & 4) != 0;
  options.buildUnindexedObjects = (flags & 8) != 0;
  options.nestingLimit = (flags & 16) ? 8 : 64;
  options.clearBuilderBeforeParse = true;
  options.paddingBehavior = (flags & 32) ? Options::PaddingBehavior::UsePadding
                                         : Options::PaddingBehavior::NoPadding;

  try {
    Parser parser(&options);
    parser.parse(reinterpret_cast<char const*>(data), size);
    std::shared_ptr<Builder> builder = parser.steal();
    Slice s = builder->slice();

    Validator validator(&options);
    validator.validate(s.start(), s.byteSize(), true);

    Options dumpOptions = options;
    dumpOptions.prettyPrint = (flags & 64) != 0;
    dumpOptions.escapeUnicode = (flags & 128) != 0;
    dumpOptions.unsupportedTypeBehavior = Options::NullifyUnsupportedType;
    std::string out;
    StringSink sink(&out);
    Dumper dumper(&sink, &dumpOptions);
    dumper.dump(s);

    // The dumped output must parse again.
    Parser reparse(&options);
    reparse.parse(out);
    Slice s2 = reparse.builder().slice();
    (void)s2.byteSize();
    (void)s.normalizedHash();
    (void)s.hash();
  } catch (Exception const&) {
  } catch (std::bad_alloc const&) {
  }
  return 0;
}
