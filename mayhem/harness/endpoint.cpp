// Fuzzes endpoint specification parsing (tcp://, ssl://, unix://, http+tcp:// ...).
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "Endpoint/Endpoint.h"

using arangodb::Endpoint;

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  std::string spec(reinterpret_cast<char const*>(data), size);
  (void)Endpoint::uriForm(spec);
  std::string unified = Endpoint::unifiedForm(spec);
  std::unique_ptr<Endpoint> server(Endpoint::serverFactory(spec, 1, true));
  std::unique_ptr<Endpoint> client(Endpoint::clientFactory(spec));
  for (auto* ep : {server.get(), client.get()}) {
    if (ep != nullptr) {
      (void)ep->host();
      (void)ep->port();
      (void)ep->hostAndPort();
      (void)ep->specification();
      (void)ep->domain();
    }
  }
  return 0;
}
