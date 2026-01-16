#include "doctest/doctest.hpp"

#include <array>
#include <span>
#include <string>
#include <string_view>

#include "gdbstub/gdbstub.hpp"
#include "gdbstub/rsp_core.hpp"

namespace {

std::span<const std::byte> as_bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

std::string bytes_to_string(std::span<const std::byte> data) {
  return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

} // namespace

TEST_CASE("version is non-empty") { CHECK_FALSE(gdbstub::version().empty()); }

TEST_CASE("build_packet uses expected checksum") {
  auto packet = gdbstub::rsp::build_packet("m123,4");
  CHECK(packet == "$m123,4#63");
}

TEST_CASE("stream_parser handles fragmented packets") {
  gdbstub::rsp::stream_parser parser;

  parser.append(as_bytes("$m123"));
  CHECK_FALSE(parser.has_event());

  parser.append(as_bytes(",4#63"));
  REQUIRE(parser.has_event());

  auto event = parser.pop_event();
  CHECK(event.kind == gdbstub::rsp::event_kind::packet);
  CHECK(event.payload == "m123,4");
  CHECK(event.checksum_ok);
}

TEST_CASE("stream_parser reports checksum failures") {
  gdbstub::rsp::stream_parser parser;

  parser.append(as_bytes("$?#3e"));
  REQUIRE(parser.has_event());

  auto event = parser.pop_event();
  CHECK(event.kind == gdbstub::rsp::event_kind::packet);
  CHECK(event.payload == "?");
  CHECK_FALSE(event.checksum_ok);
}

TEST_CASE("stream_parser emits ack and interrupt events") {
  gdbstub::rsp::stream_parser parser;

  parser.append(as_bytes("+-"));
  REQUIRE(parser.has_event());
  CHECK(parser.pop_event().kind == gdbstub::rsp::event_kind::ack);
  REQUIRE(parser.has_event());
  CHECK(parser.pop_event().kind == gdbstub::rsp::event_kind::nack);

  std::string interrupt(1, gdbstub::rsp::interrupt_char);
  parser.append(as_bytes(interrupt));
  REQUIRE(parser.has_event());
  CHECK(parser.pop_event().kind == gdbstub::rsp::event_kind::interrupt);
}

TEST_CASE("hex encoding round-trips") {
  std::array<std::byte, 4> data = {
      std::byte{0x01}, std::byte{0x02}, std::byte{0xaa}, std::byte{0xff},
  };
  auto hex = gdbstub::rsp::encode_hex(data);
  std::array<std::byte, 4> decoded{};
  REQUIRE(gdbstub::rsp::decode_hex(hex, decoded));
  CHECK(decoded == data);
}

TEST_CASE("hex decoding rejects invalid input") {
  std::array<std::byte, 2> out{};
  CHECK_FALSE(gdbstub::rsp::decode_hex("0", out));
  CHECK_FALSE(gdbstub::rsp::decode_hex("zz", out));
}

TEST_CASE("binary escaping round-trips") {
  std::array<std::byte, 5> data = {
      std::byte{'$'}, std::byte{'#'}, std::byte{'}'}, std::byte{0x11}, std::byte{0x7f},
  };
  auto escaped = gdbstub::rsp::escape_binary(data);
  auto roundtrip = escaped;
  gdbstub::rsp::unescape_binary(roundtrip);
  CHECK(roundtrip == bytes_to_string(data));
}
