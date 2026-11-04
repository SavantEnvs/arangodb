// Known-answer probes over the same ArangoDB/velocypack code the fuzz targets exercise.
// Built with the project's normal flags (no sanitizers); mayhem/test.sh compares every
// `name=value` line against the expected value.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <map>
#include <memory>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include <velocypack/Buffer.h>
#include <velocypack/Builder.h>
#include <velocypack/Dumper.h>
#include <velocypack/Exception.h>
#include <velocypack/Options.h>
#include <velocypack/Parser.h>
#include <velocypack/Sink.h>
#include <velocypack/Slice.h>
#include <velocypack/Validator.h>

#include "Basics/AttributeNameParser.h"
#include "Basics/EncodingUtils.h"
#include "Basics/ResultT.h"
#include "Basics/StringUtils.h"
#include "Basics/csv.h"
#include "Basics/datetime.h"
#include "Basics/voc-errors.h"
#include "Endpoint/Endpoint.h"
#include "ProgramOptions/IniFileParser.h"
#include "ProgramOptions/Parameters.h"
#include "ProgramOptions/ProgramOptions.h"

#define private public
#include "Rest/HttpRequest.h"
#undef private

using namespace arangodb;
namespace vp = arangodb::velocypack;
namespace su = arangodb::basics::StringUtils;

static void out(char const* name, std::string const& value) {
  std::printf("%s=%s\n", name, value.c_str());
}

static std::string csvFields;
static void onField(TRI_csv_parser_t*, char const* f, size_t l, size_t row,
                    size_t col, bool) {
  csvFields += std::to_string(row) + ":" + std::to_string(col) + "[" +
               std::string(f, l) + "]";
}
static void onBegin(TRI_csv_parser_t*, size_t) {}

int main() {
  // velocypack: JSON -> VPack -> JSON
  {
    auto b = vp::Parser::fromJson(R"({ "a" : [1, 2.5, {"b": null}], "c": "dä" })");
    std::string json = b->slice().toJson();
    out("vpack.json", json);
    out("vpack.bytesize", std::to_string(b->slice().byteSize()));
    out("vpack.a1", std::to_string(b->slice().get("a").at(1).getDouble()));
    vp::Options o;
    o.prettyPrint = true;
    out("vpack.pretty_lines", [&] {
      std::string s = b->slice().toJson(&o);
      size_t n = 0;
      for (char c : s) n += c == '\n';
      return std::to_string(n);
    }());
    vp::Validator v;
    out("vpack.validate_ok", v.validate(b->slice().start(), b->slice().byteSize()) ? "1" : "0");
    std::string bad = "not json";
    try {
      vp::Parser::fromJson(bad);
      out("vpack.bad_json", "accepted");
    } catch (vp::Exception const&) {
      out("vpack.bad_json", "rejected");
    }
    uint8_t truncated[] = {0x0b, 0x10, 0x01};
    try {
      out("vpack.validate_truncated", v.validate(truncated, sizeof(truncated)) ? "1" : "0");
    } catch (vp::Exception const&) {
      out("vpack.validate_truncated", "rejected");
    }
  }

  // datetime
  {
    tp_sys_clock_ms tp;
    bool ok = basics::parseDateTime("2020-02-29T12:34:56.789Z", tp);
    out("date.parse_ok", ok ? "1" : "0");
    out("date.millis", std::to_string(tp.time_since_epoch().count()));
    out("date.format", basics::formatDate("%yyyy-%mm-%dd %hh:%ii:%ss.%fff", tp));
    tp_sys_clock_ms tp2;
    out("date.parse_bad", basics::parseDateTime("2020-13-45", tp2) ? "1" : "0");
    basics::ParsedDuration d;
    bool dok = basics::parseIsoDuration("P1Y2M3DT4H5M6S", d);
    out("date.duration", std::string(dok ? "ok " : "bad ") + std::to_string(d.years) + "/" +
                             std::to_string(d.months) + "/" + std::to_string(d.days) + "/" +
                             std::to_string(d.hours) + "/" + std::to_string(d.minutes) + "/" +
                             std::to_string(d.seconds));
    out("date.duration_bad", basics::parseIsoDuration("1Y", d) ? "1" : "0");
  }

  // string utils
  {
    out("str.urlencode", su::urlEncode(std::string_view("a b/\xc3\xbc&=")));
    out("str.urldecode", su::urlDecode(std::string_view("a%20b%2Fc+d")));
    out("str.hex", su::encodeHex(std::string_view("abc\xff")));
    out("str.unhex", su::decodeHex(std::string_view("616263")));
    out("str.int64", std::to_string(su::int64(std::string_view("-1234"))));
    out("str.uint64", std::to_string(su::uint64(std::string_view("18446744073709551615"))));
    out("str.double", su::ftoa(su::doubleDecimal(std::string_view("2.5e2"))));
    out("str.split", su::join(su::split(std::string_view("a,b,,c"), ','), '|'));
    out("str.trim", "[" + su::trim(std::string_view("  x y \t\n")) + "]");
    out("str.soundex", su::soundex(std::string_view("Robert")));
    out("str.levenshtein", std::to_string(su::levenshteinDistance("kitten", 6, "sitting", 7)));
    out("str.escape", su::escapeUnicode(std::string_view("a\"\xc3\xa4\n")));
    out("str.formatsize", su::formatSize(5 * 1024 * 1024));
    out("str.replace", su::replace(std::string_view("aXbXc"), "X", "--"));
    out("str.tolower", su::tolower(std::string_view("AbC")));
    out("str.itoa", su::itoa(uint64_t(9876543210ULL)));
  }

  // csv
  {
    TRI_csv_parser_t p;
    TRI_InitCsvParser(&p, onBegin, onField, onField, nullptr);
    TRI_SetSeparatorCsvParser(&p, ',');
    TRI_SetQuoteCsvParser(&p, '"', true);
    std::string in = "a,\"b,c\",d\n1,\"x\"\"y\",3\n";
    TRI_ParseCsvString(&p, in.data(), in.size());
    TRI_DestroyCsvParser(&p);
    out("csv.fields", csvFields);
  }

  // attribute names
  {
    std::vector<basics::AttributeName> names;
    basics::TRI_ParseAttributeString("a.b[*].c", names, true);
    std::string s;
    for (auto const& n : names) s += n.name + (n.shouldExpand ? "*" : "") + "/";
    out("attr.parse", s);
    out("attr.count", std::to_string(names.size()));
  }

  // endpoints
  {
    out("endpoint.unified", Endpoint::unifiedForm("tcp://127.0.0.1:8529"));
    out("endpoint.unified_ssl", Endpoint::unifiedForm("SSL://localhost"));
    out("endpoint.unified_bad", Endpoint::unifiedForm("bogus://x"));
    out("endpoint.uri", Endpoint::uriForm("tcp://127.0.0.1:8529"));
    std::unique_ptr<Endpoint> ep(Endpoint::clientFactory("tcp://127.0.0.1:8530"));
    out("endpoint.hostport", ep ? ep->hostAndPort() : "null");
    out("endpoint.port", ep ? std::to_string(ep->port()) : "null");
    std::unique_ptr<Endpoint> bad(Endpoint::clientFactory("bogus"));
    out("endpoint.bad", bad ? "created" : "null");
  }

  // compression
  {
    static unsigned char const gz[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                                       0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca,
                                       0x49, 0x01, 0x00, 0x85, 0x11, 0x4a, 0x0d, 0x0b, 0x00, 0x00, 0x00};
    std::string r;
    auto rc = encoding::gzipUncompress(gz, sizeof(gz), r);
    out("enc.gunzip", std::string(rc == TRI_ERROR_NO_ERROR ? "ok:" : "err:") + r);
    std::string text(1000, 'z');
    vp::Buffer<uint8_t> packed;
    (void)encoding::zlibDeflate(reinterpret_cast<uint8_t const*>(text.data()), text.size(), packed);
    std::string back;
    (void)encoding::zlibInflate(packed.data(), packed.size(), back);
    out("enc.zlib_roundtrip", std::to_string(back == text) + ":" + std::to_string(packed.size() < 100));
    std::string junk;
    out("enc.gunzip_bad", std::to_string(encoding::gzipUncompress(reinterpret_cast<uint8_t const*>("nope nope nope"), 14, junk) == TRI_ERROR_NO_ERROR));
  }

  // ini
  {
    options::ProgramOptions po("kat", "usage", "more", "/tmp/kat");
    std::string name;
    uint64_t threads = 0;
    bool flag = false;
    po.addSection("server", "server");
    po.addOption("--server.name", "n", new options::StringParameter(&name));
    po.addOption("--server.threads", "t", new options::UInt64Parameter(&threads));
    po.addOption("--server.flag", "f", new options::BooleanParameter(&flag));
    options::IniFileParser parser(&po);
    bool ok = parser.parseContent("kat.conf", "# comment\n[server]\nname = hello world\nthreads=12\nflag = true\n", true);
    out("ini.parse", std::string(ok ? "ok " : "fail ") + name + "/" + std::to_string(threads) + "/" + (flag ? "t" : "f"));
    options::ProgramOptions po2("kat", "usage", "more", "/tmp/kat");
    po2.addSection("server", "server");
    po2.addOption("--server.threads", "t", new options::UInt64Parameter(&threads));
    options::IniFileParser parser2(&po2);
    out("ini.unknown", parser2.parseContent("kat.conf", "[server]\nnosuch = 1\n", true) ? "ok" : "fail");
  }

  // http request
  {
    ConnectionInfo ci;
    HttpRequest req(ci, 1);
    std::string url = "/_db/test/_api/doc?x=1&y=a%20b&z[]=p&z[]=q";
    req.parseUrl(url.data(), url.size());
    std::string vals;
    std::map<std::string, std::string> sorted(req.values().begin(), req.values().end());
    for (auto const& kv : sorted) vals += kv.first + "=" + kv.second + ";";
    out("http.values", vals);
    out("http.db", req.databaseName());
    out("http.path", std::string(req.requestPath()));
    out("http.array", std::to_string(req.arrayValues().size()));
    HttpRequest req2(ci, 2);
    std::string cookie = "a=1; b=hello%20world";
    std::vector<char> buf(cookie.begin(), cookie.end());
    buf.push_back('\0');
    req2.parseCookies(buf.data(), cookie.size());
    out("http.cookie_b", req2.cookieValue("b"));
  }
  return 0;
}
