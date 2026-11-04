// Fuzzes the gzip / zlib / lz4 body decoders and checks compress->uncompress round-trips.
#include <cstddef>
#include <cstdint>
#include <string>

#include <velocypack/Buffer.h>

#include "Basics/EncodingUtils.h"
#include "Basics/ErrorCode.h"
#include "Basics/voc-errors.h"

using namespace arangodb;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  if (size < 1) {
    return 0;
  }
  uint8_t sel = data[0];
  ++data;
  --size;
  constexpr size_t kMax = 1 << 20;

  std::string out;
  velocypack::Buffer<uint8_t> vout;
  switch (sel % 3) {
    case 0:
      (void)encoding::gzipUncompress(data, size, out, kMax);
      (void)encoding::gzipUncompress(data, size, vout, kMax);
      break;
    case 1:
      (void)encoding::zlibInflate(data, size, out, kMax);
      (void)encoding::zlibInflate(data, size, vout, kMax);
      break;
    default:
      (void)encoding::lz4Uncompress(data, size, vout, kMax);
      break;
  }

  // round trip the raw input through every codec
  if (size > 0 && size <= kMax) {
    velocypack::Buffer<uint8_t> packed;
    std::string back;
    if (encoding::gzipCompress(data, size, packed) == TRI_ERROR_NO_ERROR) {
      if (encoding::gzipUncompress(packed.data(), packed.size(), back, kMax + 1) != TRI_ERROR_NO_ERROR ||
          back != std::string(reinterpret_cast<char const*>(data), size)) {
        __builtin_trap();
      }
    }
    packed.clear();
    back.clear();
    if (encoding::zlibDeflate(data, size, packed) == TRI_ERROR_NO_ERROR) {
      if (encoding::zlibInflate(packed.data(), packed.size(), back, kMax + 1) != TRI_ERROR_NO_ERROR ||
          back != std::string(reinterpret_cast<char const*>(data), size)) {
        __builtin_trap();
      }
    }
    packed.clear();
    velocypack::Buffer<uint8_t> unpacked;
    // empty payloads are rejected by the codecs by design
    if (encoding::lz4Compress(data, size, packed) == TRI_ERROR_NO_ERROR) {
      if (encoding::lz4Uncompress(packed.data(), packed.size(), unpacked, kMax + 1) != TRI_ERROR_NO_ERROR ||
          unpacked.size() != size) {
        __builtin_trap();
      }
    }
  }
  return 0;
}
