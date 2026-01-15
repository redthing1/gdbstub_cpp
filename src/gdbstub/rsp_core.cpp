#include "gdbstub/rsp_core.hpp"

#include <algorithm>
#include <array>

namespace gdbstub::rsp {

namespace {

constexpr std::array<char, 16> k_hex = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

std::optional<uint8_t> hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<uint8_t>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<uint8_t>(c - 'a' + 10);
  }
  if (c >= 'A' && c <= 'F') {
    return static_cast<uint8_t>(c - 'A' + 10);
  }
  return std::nullopt;
}

} // namespace

void stream_parser::append(std::span<const std::byte> data) {
  for (std::byte b : data) {
    char c = static_cast<char>(std::to_integer<unsigned char>(b));

    if (c == packet_start) {
      payload_.clear();
      state_ = state::payload;
      continue;
    }

    switch (state_) {
    case state::idle:
      if (c == ack_char) {
        push_event({event_kind::ack, {}, true});
      } else if (c == nack_char) {
        push_event({event_kind::nack, {}, true});
      } else if (c == interrupt_char) {
        push_event({event_kind::interrupt, {}, true});
      }
      break;
    case state::payload:
      if (c == packet_end) {
        state_ = state::checksum_1;
      } else {
        payload_.push_back(c);
      }
      break;
    case state::checksum_1:
      checksum_[0] = c;
      state_ = state::checksum_2;
      break;
    case state::checksum_2: {
      checksum_[1] = c;
      uint8_t expected = 0;
      bool hex_ok = parse_hex_byte(checksum_[0], checksum_[1], expected);
      bool checksum_ok = hex_ok && checksum(payload_) == expected;
      input_event event;
      event.kind = event_kind::packet;
      event.payload = payload_;
      event.checksum_ok = checksum_ok;
      push_event(std::move(event));
      payload_.clear();
      state_ = state::idle;
      break;
    }
    }
  }
}

bool stream_parser::has_event() const { return !events_.empty(); }

input_event stream_parser::pop_event() {
  if (events_.empty()) {
    return {};
  }
  input_event event = std::move(events_.front());
  events_.pop_front();
  return event;
}

void stream_parser::reset() {
  state_ = state::idle;
  payload_.clear();
  events_.clear();
  checksum_[0] = 0;
  checksum_[1] = 0;
}

void stream_parser::push_event(input_event event) { events_.push_back(std::move(event)); }

uint8_t checksum(std::string_view payload) {
  uint8_t sum = 0;
  for (unsigned char c : payload) {
    sum = static_cast<uint8_t>(sum + c);
  }
  return sum;
}

std::string build_packet(std::string_view payload) {
  uint8_t sum = checksum(payload);
  std::string packet;
  packet.reserve(payload.size() + 4);
  packet.push_back(packet_start);
  packet.append(payload.data(), payload.size());
  packet.push_back(packet_end);
  packet.push_back(k_hex[(sum >> 4) & 0x0f]);
  packet.push_back(k_hex[sum & 0x0f]);
  return packet;
}

bool parse_hex_byte(char hi, char lo, uint8_t& out) {
  auto hi_val = hex_value(hi);
  auto lo_val = hex_value(lo);
  if (!hi_val || !lo_val) {
    return false;
  }
  out = static_cast<uint8_t>((*hi_val << 4) | *lo_val);
  return true;
}

bool decode_hex(std::string_view hex, std::span<std::byte> out) {
  if (hex.size() != out.size() * 2) {
    return false;
  }

  for (size_t i = 0; i < out.size(); ++i) {
    uint8_t value = 0;
    if (!parse_hex_byte(hex[i * 2], hex[i * 2 + 1], value)) {
      return false;
    }
    out[i] = static_cast<std::byte>(value);
  }
  return true;
}

std::string encode_hex(std::span<const std::byte> data) {
  std::string out;
  out.resize(data.size() * 2);

  for (size_t i = 0; i < data.size(); ++i) {
    uint8_t value = std::to_integer<uint8_t>(data[i]);
    out[i * 2] = k_hex[(value >> 4) & 0x0f];
    out[i * 2 + 1] = k_hex[value & 0x0f];
  }

  return out;
}

std::string escape_binary(std::span<const std::byte> data) {
  std::string out;
  out.reserve(data.size());

  for (std::byte b : data) {
    char c = static_cast<char>(std::to_integer<unsigned char>(b));
    if (c == '$' || c == '#' || c == '}') {
      out.push_back('}');
      out.push_back(static_cast<char>(c ^ 0x20));
    } else {
      out.push_back(c);
    }
  }

  return out;
}

size_t unescape_binary(std::string& data) {
  size_t write = 0;
  for (size_t i = 0; i < data.size(); ++i) {
    char c = data[i];
    if (c == '}' && i + 1 < data.size()) {
      data[write++] = static_cast<char>(data[i + 1] ^ 0x20);
      ++i;
    } else {
      data[write++] = c;
    }
  }
  data.resize(write);
  return write;
}

} // namespace gdbstub::rsp
