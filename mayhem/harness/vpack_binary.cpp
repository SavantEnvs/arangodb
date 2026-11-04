// Fuzzes the velocypack binary validator and, for valid input, slice traversal.
#include <cstddef>
#include <cstdint>
#include <string>

#include <velocypack/Builder.h>
#include <velocypack/Collection.h>
#include <velocypack/Dumper.h>
#include <velocypack/Exception.h>
#include <velocypack/Iterator.h>
#include <velocypack/Options.h>
#include <velocypack/Sink.h>
#include <velocypack/Slice.h>
#include <velocypack/Validator.h>

using namespace arangodb::velocypack;

static void walk(Slice s, int depth) {
  if (depth > 200) {
    return;
  }
  (void)s.byteSize();
  (void)s.hash();
  (void)s.normalizedHash();
  (void)s.head();
  switch (s.type()) {
    case ValueType::Array: {
      ArrayIterator it(s);
      for (; it.valid(); it.next()) {
        walk(it.value(), depth + 1);
      }
      if (s.length() > 0) {
        walk(s.at(s.length() - 1), depth + 1);
      }
      break;
    }
    case ValueType::Object: {
      ObjectIterator it(s);
      for (; it.valid(); it.next()) {
        walk(it.key(), depth + 1);
        walk(it.value(), depth + 1);
        (void)s.get(it.key().stringView());
      }
      (void)s.hasKey("a");
      (void)s.get(std::vector<std::string>{"a", "b"});
      break;
    }
    case ValueType::String:
      (void)s.stringView();
      break;
    case ValueType::Binary:
      { ValueLength bl; (void)s.getBinary(bl); }
      break;
    case ValueType::Int:
    case ValueType::UInt:
    case ValueType::SmallInt:
    case ValueType::Double:
      (void)s.getNumber<double>();
      break;
    default:
      break;
  }
}

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
  options.disallowExternals = true;  // externals dereference raw pointers
  options.disallowCustom = (flags & 8) != 0;
  options.disallowTags = (flags & 16) != 0;
  options.disallowBCD = (flags & 32) != 0;

  try {
    Validator validator(&options);
    if (!validator.validate(data, size, (flags & 64) != 0)) {
      return 0;
    }
    if (!options.validateUtf8Strings) {
      // Dumper and normalizedHash require UTF-8-validated strings; stop after exercising the validator.
      return 0;
    }
    Slice s(data);
    walk(s, 0);

    Options dumpOptions;
    dumpOptions.unsupportedTypeBehavior = Options::NullifyUnsupportedType;
    dumpOptions.prettyPrint = (flags & 128) != 0;
    std::string out;
    StringSink sink(&out);
    Dumper dumper(&sink, &dumpOptions);
    dumper.dump(s);

    Builder b;
    b.add(s);
    (void)Collection::keys(s.isObject() ? s : Slice::emptyObjectSlice());
  } catch (Exception const&) {
  } catch (std::bad_alloc const&) {
  }
  return 0;
}
