#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gdbstub::rsp {

constexpr char packet_start = '$';
constexpr char notification_start = '%';
constexpr char packet_end = '#';
constexpr char ack_char = '+';
constexpr char nack_char = '-';
constexpr char interrupt_char = '\x03';

enum class event_kind {
  packet,
  notification,
  ack,
  nack,
  interrupt,
};

struct input_event {
  event_kind kind = event_kind::packet;
  std::string payload;
  bool checksum_ok = true;
};

class stream_parser {
public:
  void append(std::span<const std::byte> data);
  bool has_event() const;
  input_event pop_event();
  void reset();

private:
  enum class state { idle, payload, checksum_1, checksum_2 };

  state state_ = state::idle;
  std::string payload_;
  char checksum_[2] = {0, 0};
  event_kind current_kind_ = event_kind::packet;
  std::deque<input_event> events_;

  void push_event(input_event event);
};

uint8_t checksum(std::string_view payload);
std::string build_packet(std::string_view payload);
std::string build_notification(std::string_view payload);
bool parse_hex_byte(char hi, char lo, uint8_t& out);
bool decode_hex(std::string_view hex, std::span<std::byte> out);
std::string encode_hex(std::span<const std::byte> data);
std::string escape_binary(std::span<const std::byte> data);
size_t unescape_binary(std::string& data);

} // namespace gdbstub::rsp
