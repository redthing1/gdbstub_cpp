#include "gdbstub/server.hpp"

#include "gdbstub/gdbstub.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <limits>
#include <sstream>

namespace gdbstub {

namespace {

constexpr size_t k_max_packet_size = 4096;
constexpr size_t k_max_memory_read = 2048;

std::span<const std::byte> as_bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

std::string hex_encode_string(std::string_view value) {
  if (value.empty()) {
    return {};
  }
  return rsp::encode_hex(as_bytes(value));
}

bool decode_hex_string(std::string_view value, std::string& out) {
  out.clear();
  if (value.empty()) {
    return true;
  }
  if (value.size() % 2 != 0) {
    return false;
  }
  std::vector<std::byte> buffer(value.size() / 2);
  if (!rsp::decode_hex(value, buffer)) {
    return false;
  }
  out.assign(reinterpret_cast<const char*>(buffer.data()), buffer.size());
  return true;
}

std::optional<process_launch_request> parse_vrun_request(std::string_view args) {
  process_launch_request request;
  if (args.empty()) {
    return request;
  }
  if (args[0] == ';') {
    args.remove_prefix(1);
    if (args.empty()) {
      return request;
    }
  }

  bool first = true;
  size_t start = 0;
  while (start <= args.size()) {
    auto next = args.find(';', start);
    auto part = args.substr(start, next == std::string_view::npos ? args.size() - start : next - start);
    std::string decoded;
    if (!decode_hex_string(part, decoded)) {
      return std::nullopt;
    }
    if (first) {
      if (!decoded.empty()) {
        request.filename = decoded;
      }
    } else {
      request.args.push_back(decoded);
    }
    if (next == std::string_view::npos) {
      break;
    }
    start = next + 1;
    first = false;
  }

  return request;
}

std::string hex_byte(uint8_t value) {
  char buf[3] = {0};
  std::snprintf(buf, sizeof(buf), "%02x", value);
  return std::string(buf);
}

std::string hex_u64(uint64_t value, size_t width = 0) {
  char buf[32] = {0};
  if (width > 0) {
    std::snprintf(buf, sizeof(buf), "%0*llx", static_cast<int>(width), static_cast<unsigned long long>(value));
  } else {
    std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(value));
  }
  return std::string(buf);
}

bool parse_hex_u64(std::string_view text, uint64_t& value) {
  value = 0;
  if (text.empty()) {
    return false;
  }
  auto result = std::from_chars(text.data(), text.data() + text.size(), value, 16);
  return result.ec == std::errc{};
}

std::string perms_to_string(mem_perm perms) {
  if (perms == mem_perm::none) {
    return {};
  }
  std::string out;
  out.push_back(has_perm(perms, mem_perm::read) ? 'r' : '-');
  out.push_back(has_perm(perms, mem_perm::write) ? 'w' : '-');
  out.push_back(has_perm(perms, mem_perm::exec) ? 'x' : '-');
  return out;
}

uint64_t address_space_end(const target_view& target, const arch_spec& arch) {
  auto bits = arch.address_bits;
  if (target.host) {
    if (auto info = target.host->get_host_info()) {
      if (info->addressing_bits) {
        bits = *info->addressing_bits;
      } else if (info->ptr_size > 0) {
        bits = info->ptr_size * 8;
      }
    }
  }
  if (!bits && target.process) {
    if (auto info = target.process->get_process_info()) {
      if (info->ptr_size > 0) {
        bits = info->ptr_size * 8;
      }
    }
  }
  if (!bits || *bits <= 0 || *bits >= 63) {
    return std::numeric_limits<uint64_t>::max();
  }
  return 1ULL << *bits;
}

bool parse_dec_int(std::string_view text, int& value) {
  value = 0;
  if (text.empty()) {
    return false;
  }
  auto result = std::from_chars(text.data(), text.data() + text.size(), value, 10);
  return result.ec == std::errc{};
}

bool parse_thread_token(std::string_view text, std::optional<uint64_t>& tid) {
  if (text == "-1" || text == "0") {
    tid.reset();
    return true;
  }
  uint64_t parsed = 0;
  if (!parse_hex_u64(text, parsed)) {
    return false;
  }
  tid = parsed;
  return true;
}

enum class vcont_parse_result { none, ok, invalid };

struct vcont_selection {
  char action = 0;
  std::optional<int> signal;
  std::optional<address_range> range;
};

struct breakpoint_suffixes {
  bool has_thread = false;
  bool has_cond_list = false;
  bool has_cmds = false;
  std::optional<uint64_t> thread_id;
  std::vector<bytecode_expr> conditions;
  std::optional<breakpoint_commands> commands;
};

struct breakpoint_parse_result {
  int type = 0;
  uint64_t addr = 0;
  uint64_t kind = 0;
  breakpoint_suffixes suffixes{};
};

vcont_parse_result parse_vcont_actions(std::string_view actions,
                                       uint64_t current_tid,
                                       vcont_selection& out) {
  out = {};
  size_t start = 0;
  while (start < actions.size()) {
    auto next = actions.find(';', start);
    auto part = actions.substr(start, next == std::string_view::npos ? actions.size() - start : next - start);
    if (!part.empty()) {
      char action = part[0];
      auto colon = part.find(':');
      std::string_view signal_str = colon == std::string_view::npos ? part.substr(1) : part.substr(1, colon - 1);
      std::string_view thread_str = colon == std::string_view::npos ? std::string_view{} : part.substr(colon + 1);

      bool applies = true;
      if (!thread_str.empty()) {
        std::optional<uint64_t> tid;
        if (!parse_thread_token(thread_str, tid)) {
          applies = false;
        } else if (tid && *tid != current_tid) {
          applies = false;
        }
      }

      if (applies) {
        out.action = action;
        if (action == 'r') {
          auto comma = signal_str.find(',');
          if (comma == std::string_view::npos) {
            return vcont_parse_result::invalid;
          }
          uint64_t range_start = 0;
          uint64_t range_end = 0;
          if (!parse_hex_u64(signal_str.substr(0, comma), range_start) ||
              !parse_hex_u64(signal_str.substr(comma + 1), range_end)) {
            return vcont_parse_result::invalid;
          }
          out.range = address_range{range_start, range_end};
        } else if (action != 't' && !signal_str.empty()) {
          uint64_t parsed = 0;
          if (parse_hex_u64(signal_str, parsed) && parsed > 0) {
            out.signal = static_cast<int>(parsed);
          }
        }
        return vcont_parse_result::ok;
      }
    }

    if (next == std::string_view::npos) {
      break;
    }
    start = next + 1;
  }

  return vcont_parse_result::none;
}

bool split_thread_suffix(std::string_view payload, std::string_view& base, std::optional<uint64_t>& tid) {
  auto pos = payload.rfind(";thread:");
  if (pos == std::string_view::npos) {
    base = payload;
    return true;
  }

  auto end = payload.find(';', pos + 8);
  if (end == std::string_view::npos || end != payload.size() - 1) {
    return false;
  }

  auto id_str = payload.substr(pos + 8, end - (pos + 8));
  if (id_str.empty()) {
    return false;
  }

  if (!parse_thread_token(id_str, tid)) {
    return false;
  }

  base = payload.substr(0, pos);
  return true;
}

bool parse_bytecode_list(std::string_view input, std::vector<bytecode_expr>& out) {
  out.clear();
  if (input.empty()) {
    return false;
  }

  size_t pos = 0;
  while (pos < input.size()) {
    if (input[pos] != 'X') {
      return false;
    }
    ++pos;
    auto comma = input.find(',', pos);
    if (comma == std::string_view::npos) {
      return false;
    }
    auto len_str = input.substr(pos, comma - pos);
    if (len_str.empty()) {
      return false;
    }
    uint64_t byte_len = 0;
    if (!parse_hex_u64(len_str, byte_len)) {
      return false;
    }
    if (byte_len > std::numeric_limits<size_t>::max() / 2) {
      return false;
    }
    size_t hex_len = static_cast<size_t>(byte_len) * 2;
    pos = comma + 1;
    if (pos + hex_len > input.size()) {
      return false;
    }
    std::vector<std::byte> buffer(static_cast<size_t>(byte_len));
    if (!rsp::decode_hex(input.substr(pos, hex_len), buffer)) {
      return false;
    }
    out.push_back(bytecode_expr{std::move(buffer)});
    pos += hex_len;
  }
  return !out.empty();
}

bool parse_breakpoint_commands(std::string_view input, breakpoint_commands& out) {
  out = {};
  auto comma = input.find(',');
  if (comma == std::string_view::npos) {
    return false;
  }
  auto persist_str = input.substr(0, comma);
  if (persist_str.empty()) {
    return false;
  }
  int persist = 0;
  if (!parse_dec_int(persist_str, persist)) {
    return false;
  }
  out.persist = persist != 0;
  auto list = input.substr(comma + 1);
  if (!parse_bytecode_list(list, out.commands)) {
    return false;
  }
  return true;
}

bool parse_breakpoint_suffixes(std::string_view suffix, breakpoint_suffixes& out) {
  out = {};
  if (suffix.empty()) {
    return true;
  }

  size_t start = 0;
  while (start < suffix.size()) {
    auto next = suffix.find(';', start);
    auto part = suffix.substr(start, next == std::string_view::npos ? suffix.size() - start : next - start);
    if (!part.empty()) {
      if (part.rfind("thread:", 0) == 0) {
        if (out.has_thread) {
          return false;
        }
        auto id_str = part.substr(std::string_view("thread:").size());
        if (id_str.empty()) {
          return false;
        }
        if (!parse_thread_token(id_str, out.thread_id)) {
          return false;
        }
        out.has_thread = true;
      } else if (part.rfind("cmds:", 0) == 0) {
        if (out.has_cmds) {
          return false;
        }
        breakpoint_commands commands;
        if (!parse_breakpoint_commands(part.substr(std::string_view("cmds:").size()), commands)) {
          return false;
        }
        out.commands = std::move(commands);
        out.has_cmds = true;
      } else if (part.front() == 'X') {
        if (out.has_cond_list) {
          return false;
        }
        if (!parse_bytecode_list(part, out.conditions)) {
          return false;
        }
        out.has_cond_list = true;
      } else {
        return false;
      }
    }

    if (next == std::string_view::npos) {
      break;
    }
    start = next + 1;
  }
  return true;
}

bool parse_breakpoint_packet(std::string_view args, breakpoint_parse_result& out) {
  out = {};
  auto first = args.find(',');
  auto second = args.find(',', first + 1);
  if (first == std::string_view::npos || second == std::string_view::npos) {
    return false;
  }

  if (!parse_dec_int(args.substr(0, first), out.type)) {
    return false;
  }

  auto suffix_pos = args.find(';', second + 1);
  std::string_view kind_str = suffix_pos == std::string_view::npos
                                  ? args.substr(second + 1)
                                  : args.substr(second + 1, suffix_pos - (second + 1));

  if (!parse_hex_u64(args.substr(first + 1, second - first - 1), out.addr) ||
      !parse_hex_u64(kind_str, out.kind)) {
    return false;
  }

  if (suffix_pos != std::string_view::npos) {
    auto suffix = args.substr(suffix_pos + 1);
    if (!parse_breakpoint_suffixes(suffix, out.suffixes)) {
      return false;
    }
  }

  return true;
}

std::string escape_json_string(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (unsigned char c : value) {
    switch (c) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (c < 0x20) {
        char buf[7] = {0};
        std::snprintf(buf, sizeof(buf), "\\u%04x", c);
        out += buf;
      } else {
        out.push_back(static_cast<char>(c));
      }
      break;
    }
  }
  return out;
}

std::optional<uint64_t> parse_json_thread_id(std::string_view json) {
  auto key = json.find("\"thread\"");
  if (key == std::string_view::npos) {
    return std::nullopt;
  }
  auto colon = json.find(':', key + 8);
  if (colon == std::string_view::npos) {
    return std::nullopt;
  }
  size_t pos = colon + 1;
  while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
    ++pos;
  }
  if (pos >= json.size()) {
    return std::nullopt;
  }
  uint64_t tid = 0;
  auto result = std::from_chars(json.data() + pos, json.data() + json.size(), tid, 10);
  if (result.ec != std::errc{}) {
    return std::nullopt;
  }
  return tid;
}

bool parse_json_bool(std::string_view json, std::string_view key, bool& value) {
  std::string token = "\"";
  token.append(key.data(), key.size());
  token.push_back('"');
  auto key_pos = json.find(token);
  if (key_pos == std::string_view::npos) {
    return false;
  }
  auto colon = json.find(':', key_pos + token.size());
  if (colon == std::string_view::npos) {
    return false;
  }
  size_t pos = colon + 1;
  while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
    ++pos;
  }
  if (json.compare(pos, 4, "true") == 0) {
    value = true;
    return true;
  }
  if (json.compare(pos, 5, "false") == 0) {
    value = false;
    return true;
  }
  return false;
}

std::optional<uint64_t> parse_json_u64(std::string_view json, std::string_view key) {
  std::string token = "\"";
  token.append(key.data(), key.size());
  token.push_back('"');
  auto key_pos = json.find(token);
  if (key_pos == std::string_view::npos) {
    return std::nullopt;
  }
  auto colon = json.find(':', key_pos + token.size());
  if (colon == std::string_view::npos) {
    return std::nullopt;
  }
  size_t pos = colon + 1;
  while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
    ++pos;
  }
  if (pos >= json.size()) {
    return std::nullopt;
  }
  uint64_t value = 0;
  auto result = std::from_chars(json.data() + pos, json.data() + json.size(), value, 10);
  if (result.ec != std::errc{}) {
    return std::nullopt;
  }
  return value;
}

bool parse_json_u64_list(std::string_view json, std::string_view key, std::vector<uint64_t>& values) {
  values.clear();
  std::string token = "\"";
  token.append(key.data(), key.size());
  token.push_back('"');
  auto key_pos = json.find(token);
  if (key_pos == std::string_view::npos) {
    return false;
  }
  auto colon = json.find(':', key_pos + token.size());
  if (colon == std::string_view::npos) {
    return false;
  }
  auto open = json.find('[', colon + 1);
  if (open == std::string_view::npos) {
    return false;
  }
  size_t pos = open + 1;
  while (pos < json.size()) {
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
      ++pos;
    }
    if (pos >= json.size() || json[pos] == ']') {
      break;
    }
    uint64_t value = 0;
    auto result = std::from_chars(json.data() + pos, json.data() + json.size(), value, 10);
    if (result.ec != std::errc{}) {
      return false;
    }
    values.push_back(value);
    pos = static_cast<size_t>(result.ptr - json.data());
    while (pos < json.size() && json[pos] != ',' && json[pos] != ']') {
      ++pos;
    }
    if (pos < json.size() && json[pos] == ',') {
      ++pos;
    }
  }
  return true;
}

std::string stop_reason_label(stop_kind kind) {
  switch (kind) {
  case stop_kind::sw_break:
  case stop_kind::hw_break:
    return "breakpoint";
  case stop_kind::watch_read:
  case stop_kind::watch_write:
  case stop_kind::watch_access:
    return "watchpoint";
  case stop_kind::exited:
    return "exited";
  case stop_kind::signal:
  default:
    return "signal";
  }
}

std::string build_memory_map_xml(const std::vector<memory_region>& regions) {
  std::string xml;
  xml.reserve(128 + regions.size() * 64);
  xml += "<memory-map>";
  for (const auto& region : regions) {
    xml += "<memory type=\"ram\" start=\"0x";
    xml += hex_u64(region.start);
    xml += "\" length=\"0x";
    xml += hex_u64(region.size);
    xml += "\"";
    auto perms = perms_to_string(region.perms);
    if (!perms.empty()) {
      xml += " permissions=\"";
      xml += perms;
      xml += "\"";
    }
    xml += "/>";
  }
  xml += "</memory-map>";
  return xml;
}

std::string escape_xml_attr(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (char c : value) {
    switch (c) {
    case '&':
      out += "&amp;";
      break;
    case '<':
      out += "&lt;";
      break;
    case '>':
      out += "&gt;";
      break;
    case '"':
      out += "&quot;";
      break;
    case '\'':
      out += "&apos;";
      break;
    default:
      out.push_back(c);
      break;
    }
  }
  return out;
}

std::string build_library_list_xml(const std::vector<library_entry>& libraries) {
  std::string xml;
  xml.reserve(128 + libraries.size() * 80);
  xml += "<library-list version=\"1.0\">";
  for (const auto& lib : libraries) {
    if (lib.name.empty()) {
      continue;
    }
    const bool has_segments = !lib.segments.empty();
    const bool has_sections = !lib.sections.empty();
    if (has_segments == has_sections) {
      continue;
    }

    xml += "<library name=\"";
    xml += escape_xml_attr(lib.name);
    xml += "\">";

    const auto& addrs = has_segments ? lib.segments : lib.sections;
    const char* tag = has_segments ? "segment" : "section";
    for (uint64_t addr : addrs) {
      xml += "<";
      xml += tag;
      xml += " address=\"0x";
      xml += hex_u64(addr);
      xml += "\"/>";
    }

    xml += "</library>";
  }
  xml += "</library-list>";
  return xml;
}

std::string join_types(const std::vector<std::string>& types) {
  std::string out;
  for (size_t i = 0; i < types.size(); ++i) {
    if (i > 0) {
      out += ",";
    }
    out += types[i];
  }
  return out;
}

std::string build_thread_list(const std::vector<uint64_t>& threads) {
  std::string out = "m";
  bool first = true;
  for (uint64_t tid : threads) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    out += hex_u64(tid);
  }
  return out;
}

uint8_t error_code_for_status(target_status status) {
  switch (status) {
  case target_status::fault:
    return 0x0e;
  case target_status::invalid:
    return 0x16;
  case target_status::unsupported:
    return 0x63;
  case target_status::ok:
  default:
    return 0x01;
  }
}

std::optional<breakpoint_type> parse_breakpoint_type(int value) {
  switch (value) {
  case 0:
    return breakpoint_type::software;
  case 1:
    return breakpoint_type::hardware;
  case 2:
    return breakpoint_type::watch_write;
  case 3:
    return breakpoint_type::watch_read;
  case 4:
    return breakpoint_type::watch_access;
  default:
    return std::nullopt;
  }
}

void notify_stop_thunk(void* ctx, const stop_reason& reason) {
  static_cast<server*>(ctx)->notify_stop(reason);
}

} // namespace

server::server(target target, arch_spec arch, std::unique_ptr<transport> transport)
    : target_(target.view()), arch_(std::move(arch)), transport_(std::move(transport)) {}

server::~server() { stop(); }

bool server::listen(std::string_view address) { return transport_->listen(address); }

bool server::wait_for_connection() {
  bool accepted = transport_->accept();
  if (accepted) {
    target_.run.set_stop_notifier(stop_notifier{this, notify_stop_thunk});
  }
  return accepted;
}

bool server::has_connection() const { return transport_->connected(); }

void server::serve_forever() {
  if (!wait_for_connection()) {
    return;
  }

  while (has_connection()) {
    if (!poll(std::chrono::milliseconds(100))) {
      continue;
    }
  }
}

bool server::poll(std::chrono::milliseconds timeout) {
  if (!has_connection()) {
    return false;
  }

  bool processed = read_and_process(timeout);
  processed = flush_pending_stop() || processed;

  if (exec_state_ == exec_state::running) {
    if (auto stop = target_.run.poll_stop()) {
      if (non_stop_.enabled) {
        enqueue_stop(std::move(*stop));
      } else {
        send_stop_reply(*stop);
        exec_state_ = exec_state::halted;
      }
      processed = true;
    }
  }

  maybe_send_stop_notification();
  return processed;
}

void server::notify_stop(stop_reason reason) {
  enqueue_stop(std::move(reason));
}

void server::stop() {
  target_.run.set_stop_notifier({});
  transport_->close();
}

bool server::read_and_process(std::chrono::milliseconds timeout) {
  if (!transport_->readable(timeout)) {
    return false;
  }

  std::array<std::byte, k_max_packet_size> buffer{};
  auto bytes_read = transport_->read(buffer);
  if (bytes_read <= 0) {
    transport_->disconnect();
    return false;
  }

  parser_.append(std::span<const std::byte>(buffer.data(), static_cast<size_t>(bytes_read)));

  bool processed = false;
  while (parser_.has_event()) {
    processed = process_event(parser_.pop_event()) || processed;
  }

  return processed;
}

bool server::process_event(const rsp::input_event& event) {
  switch (event.kind) {
  case rsp::event_kind::ack:
  case rsp::event_kind::nack:
    return false;
  case rsp::event_kind::interrupt:
    handle_interrupt();
    return true;
  case rsp::event_kind::notification:
    return false;
  case rsp::event_kind::packet:
    if (!event.checksum_ok) {
      if (!no_ack_mode_) {
        send_nack();
      }
      return true;
    }

    if (!no_ack_mode_) {
      send_ack();
    }
    handle_packet(event.payload);
    return true;
  default:
    return false;
  }
}

bool server::flush_pending_stop() {
  if (exec_state_ != exec_state::running) {
    return false;
  }

  if (non_stop_.enabled) {
    return false;
  }

  std::optional<stop_reason> reason;
  {
    std::lock_guard<std::mutex> lock(non_stop_.mutex);
    if (!non_stop_.pending_stops.empty()) {
      reason = std::move(non_stop_.pending_stops.front());
      non_stop_.pending_stops.pop();
    }
  }

  if (!reason) {
    return false;
  }

  send_stop_reply(*reason);
  exec_state_ = exec_state::halted;
  return true;
}

void server::handle_interrupt() {
  target_.run.interrupt();
}

void server::handle_packet(std::string_view payload) {
  if (payload.empty()) {
    send_packet("");
    return;
  }

  std::string_view base_payload = payload;
  std::optional<uint64_t> suffix_thread;
  char cmd = payload[0];

  if (thread_suffix_enabled_) {
    if (cmd == 'g' || cmd == 'G' || cmd == 'p' || cmd == 'P') {
      if (!split_thread_suffix(payload, base_payload, suffix_thread)) {
        send_error(0x16);
        return;
      }
      if (suffix_thread && target_.threads) {
        target_.threads->set_current_thread(*suffix_thread);
      }
      cmd = base_payload.empty() ? cmd : base_payload[0];
    }
  }

  auto args = base_payload.substr(1);

  switch (cmd) {
  case 'g':
    handle_read_all_registers();
    break;
  case 'G':
    handle_write_all_registers(args);
    break;
  case 'p':
    handle_read_register(args);
    break;
  case 'P':
    handle_write_register(args);
    break;
  case 'm':
    handle_read_memory(args);
    break;
  case 'x':
    handle_read_binary_memory(args);
    break;
  case 'M':
    handle_write_memory(args);
    break;
  case 'X':
    handle_write_binary_memory(args);
    break;
  case 'c':
    handle_continue(args, resume_action::cont, false);
    break;
  case 'C':
    handle_continue(args, resume_action::cont, true);
    break;
  case 's':
    handle_continue(args, resume_action::step, false);
    break;
  case 'S':
    handle_continue(args, resume_action::step, true);
    break;
  case 'b':
    if (args == "c") {
      handle_reverse(false);
    } else if (args == "s") {
      handle_reverse(true);
    } else {
      send_packet("");
    }
    break;
  case 'z':
    handle_remove_breakpoint(args);
    break;
  case 'Z':
    handle_insert_breakpoint(args);
    break;
  case 'q':
    handle_query(args);
    break;
  case 'Q':
    handle_set_query(args);
    break;
  case 'v':
    handle_v_packet(args);
    break;
  case 'j':
    handle_j_packet(base_payload);
    break;
  case 'H':
    handle_set_thread(args);
    break;
  case 'T':
    handle_thread_alive(args);
    break;
  case '?':
    handle_halt_reason();
    break;
  case 'D':
    handle_detach();
    break;
  case '!':
    handle_extended_mode();
    break;
  case 'R':
    handle_restart(args);
    break;
  case 'k':
    transport_->disconnect();
    break;
  default:
    send_packet("");
    break;
  }
}

void server::handle_query(std::string_view args) {
  if (args.rfind("Xfer:", 0) == 0) {
    handle_xfer(args.substr(5));
    return;
  }

  auto colon_pos = args.find(':');
  auto name = colon_pos == std::string_view::npos ? args : args.substr(0, colon_pos);
  auto params = colon_pos == std::string_view::npos ? std::string_view{} : args.substr(colon_pos + 1);

  if (name == "Supported") {
    auto caps = run_caps();
    auto bp_caps = breakpoint_caps();

    std::string features;
    features += "PacketSize=";
    features += hex_u64(k_max_packet_size);
    features += ";vContSupported+;QStartNoAckMode+";

    if (!arch_.target_xml.empty() && !arch_.xml_arch_name.empty()) {
      features += ";qXfer:features:read+;xmlRegisters=";
      features += arch_.xml_arch_name;
    }
    if (bp_caps.software) {
      features += ";swbreak+";
    }
    if (bp_caps.hardware) {
      features += ";hwbreak+";
    }
    if (bp_caps.supports_conditional) {
      features += ";ConditionalBreakpoints+";
    }
    if (bp_caps.supports_commands) {
      features += ";BreakpointCommands+";
    }
    if (caps.reverse_continue) {
      features += ";ReverseContinue+";
    }
    if (caps.reverse_step) {
      features += ";ReverseStep+";
    }
    if (caps.non_stop) {
      features += ";QNonStop+";
    }
    if (target_.host) {
      features += ";qHostInfo+";
    }
    if (target_.process) {
      features += ";qProcessInfo+";
    }
    if (target_.memory_layout) {
      features += ";qMemoryRegionInfo+";
    }
    if (target_.memory_layout && target_.memory_layout->has_memory_map()) {
      features += ";qXfer:memory-map:read+";
    }
    if (target_.libraries) {
      features += ";qXfer:libraries:read+";
    }
    send_packet(features);
    return;
  }

  if (name == "GDBServerVersion") {
    std::string response = "name:gdbstub_cpp;version:";
    response += gdbstub::version();
    response += ";";
    send_packet(response);
    return;
  }

  if (name == "StructuredDataPlugins") {
    send_packet("[]");
    return;
  }

  if (name.rfind("RegisterInfo", 0) == 0) {
    handle_register_info(name.substr(std::string_view("RegisterInfo").size()));
    return;
  }

  if (name.rfind("ThreadStopInfo", 0) == 0) {
    auto tid_str = name.substr(std::string_view("ThreadStopInfo").size());
    uint64_t tid = 0;
    if (tid_str.empty() || !parse_hex_u64(tid_str, tid)) {
      send_error(0x16);
      return;
    }
    std::optional<stop_reason> reason;
    if (target_.threads) {
      reason = target_.threads->thread_stop_reason(tid);
    }
    auto reply = reason.value_or(last_stop_.value_or(stop_reason{stop_kind::signal, 5}));
    reply.thread_id = tid;
    send_stop_reply(reply);
    return;
  }

  if (name == "ShlibInfoAddr") {
    handle_shlib_info_addr();
    return;
  }

  if (name == "Offsets") {
    handle_offsets();
    return;
  }

  if (name == "Attached") {
    send_packet(attached_state_ == attached_state::launched ? "0" : "1");
    return;
  }

  if (name == "C") {
    auto tid = current_thread_id().value_or(1);
    send_packet("QC" + hex_u64(tid));
    return;
  }

  if (name == "fThreadInfo") {
    send_packet(build_thread_list(thread_ids()));
    return;
  }

  if (name == "sThreadInfo") {
    send_packet("l");
    return;
  }

  if (name == "Symbol") {
    send_packet("OK");
    return;
  }

  if (name == "HostInfo") {
    handle_host_info();
    return;
  }

  if (name == "ProcessInfo") {
    handle_process_info();
    return;
  }

  if (name == "MemoryRegionInfo") {
    handle_memory_region_info(params);
    return;
  }

  send_packet("");
}

void server::handle_set_query(std::string_view args) {
  if (args == "StartNoAckMode") {
    send_packet("OK");
    no_ack_mode_ = true;
    return;
  }

  if (args == "ListThreadsInStopReply") {
    list_threads_in_stop_reply_ = true;
    send_packet("OK");
    return;
  }

  if (args == "ThreadSuffixSupported") {
    thread_suffix_enabled_ = true;
    send_packet("OK");
    return;
  }

  if (args.rfind("NonStop:", 0) == 0) {
    if (!run_caps().non_stop) {
      send_packet("");
      return;
    }
    if (args.size() != 9 || (args[8] != '0' && args[8] != '1')) {
      send_error(0x16);
      return;
    }
    non_stop_.enabled = args[8] == '1';
    reset_non_stop_state();
    send_packet("OK");
    return;
  }

  if (args.rfind("EnableErrorStrings", 0) == 0) {
    error_strings_enabled_ = true;
    send_packet("OK");
    return;
  }

  send_packet("");
}

void server::handle_v_packet(std::string_view args) {
  if (args == "Cont?") {
    auto caps = run_caps();
    std::string response = "vCont;c;C;s;S";
    if (caps.range_step) {
      response += ";r";
    }
    if (caps.non_stop) {
      response += ";t";
    }
    send_packet(response);
    return;
  }

  if (args.rfind("Run", 0) == 0) {
    handle_vrun(args.substr(3));
    return;
  }

  if (args.rfind("Attach;", 0) == 0) {
    handle_vattach(args.substr(7));
    return;
  }

  if (args.rfind("Kill", 0) == 0) {
    handle_vkill(args.substr(4));
    return;
  }

  if (args == "Stopped") {
    if (!non_stop_.enabled) {
      send_packet("");
      return;
    }
    std::optional<stop_reason> reason;
    {
      std::lock_guard<std::mutex> lock(non_stop_.mutex);
      if (!non_stop_.pending_stops.empty()) {
        reason = std::move(non_stop_.pending_stops.front());
        non_stop_.pending_stops.pop();
      }
    }
    if (!reason) {
      non_stop_.notification_in_flight = false;
      send_packet("OK");
      return;
    }
    bool include_library = consume_library_change();
    send_packet(build_stop_reply_payload(*reason, include_library));
    return;
  }

  if (args == "CtrlC") {
    handle_interrupt();
    send_packet("OK");
    return;
  }

  if (args.rfind("Cont;", 0) != 0) {
    send_packet("");
    return;
  }

  auto actions = args.substr(5);
  uint64_t current_tid = current_thread_id().value_or(1);
  vcont_selection selection;
  auto parse_result = parse_vcont_actions(actions, current_tid, selection);
  if (parse_result == vcont_parse_result::invalid) {
    send_error(0x16);
    return;
  }
  if (parse_result == vcont_parse_result::none) {
    send_stop_reply(last_stop_.value_or(stop_reason{stop_kind::signal, 5}));
    return;
  }

  auto caps = run_caps();

  if (selection.action == 't') {
    if (!non_stop_.enabled) {
      send_packet("");
      return;
    }
    non_stop_.stop_signal_zero_pending = true;
    target_.run.interrupt();
    send_packet("OK");
    return;
  }

  if (selection.action == 's' || selection.action == 'S') {
    auto result = target_.run.resume(resume_request::step(selection.signal));
    finish_resume(result, false);
    return;
  }

  if (selection.action == 'c' || selection.action == 'C') {
    auto result = target_.run.resume(resume_request::cont(selection.signal));
    finish_resume(result, false);
    return;
  }

  if (selection.action == 'r') {
    if (!caps.range_step) {
      send_packet("");
      return;
    }
    if (!selection.range) {
      send_error(0x16);
      return;
    }
    auto result = target_.run.resume(resume_request::range_step(*selection.range));
    finish_resume(result, true);
    return;
  }

  send_stop_reply(last_stop_.value_or(stop_reason{stop_kind::signal, 5}));
}

void server::handle_vrun(std::string_view args) {
  auto control = process_control();
  if (!control) {
    send_packet("");
    return;
  }

  auto request = parse_vrun_request(args);
  if (!request) {
    send_error(0x16);
    return;
  }

  auto result = control->launch(*request);
  if (!result) {
    send_packet("");
    return;
  }
  set_attached_state_if_ok(attached_state::launched, result->status);
  finish_resume(*result, true);
}

void server::handle_vattach(std::string_view args) {
  auto control = process_control();
  if (!control) {
    send_packet("");
    return;
  }

  if (args.empty()) {
    send_error(0x16);
    return;
  }

  uint64_t pid = 0;
  if (!parse_hex_u64(args, pid)) {
    send_error(0x16);
    return;
  }

  auto result = control->attach(pid);
  if (!result) {
    send_packet("");
    return;
  }
  set_attached_state_if_ok(attached_state::attached, result->status);
  finish_resume(*result, true);
}

void server::handle_vkill(std::string_view args) {
  auto control = process_control();
  if (!control) {
    send_packet("");
    return;
  }

  std::optional<uint64_t> pid;
  if (!args.empty()) {
    if (args[0] == ';') {
      args.remove_prefix(1);
    }
    if (args.empty()) {
      send_error(0x16);
      return;
    }
    uint64_t parsed = 0;
    if (!parse_hex_u64(args, parsed)) {
      send_error(0x16);
      return;
    }
    pid = parsed;
  }

  auto status = control->kill(pid);
  set_attached_state_if_ok(attached_state::unknown, status);
  send_status_error(status, true);
}

void server::handle_restart(std::string_view) {
  auto control = process_control();
  if (!control) {
    send_packet("");
    return;
  }

  auto result = control->restart();
  if (!result) {
    send_packet("");
    return;
  }
  if (result->status != target_status::ok) {
    send_status_error(result->status, true);
    return;
  }

  set_attached_state(attached_state::launched);
  if (result->state == resume_result::state::running) {
    exec_state_ = exec_state::running;
    return;
  }

  exec_state_ = exec_state::halted;
  if (result->state == resume_result::state::exited || result->stop.kind == stop_kind::exited) {
    last_stop_ = result->stop;
    return;
  }

  if (non_stop_.enabled) {
    enqueue_stop(result->stop);
    maybe_send_stop_notification();
    return;
  }

  last_stop_ = result->stop;
}

void server::handle_continue(std::string_view args, resume_action action, bool has_signal) {
  resume_request req;
  req.action = action;

  if (!args.empty()) {
    if (!args.empty() && (args[0] == ';' || args[0] == ',')) {
      args.remove_prefix(1);
    }

    auto semi = args.find(';');
    if (has_signal) {
      std::string_view signal_str = semi == std::string_view::npos ? args : args.substr(0, semi);
      uint64_t sig = 0;
      if (parse_hex_u64(signal_str, sig)) {
        req.signal = static_cast<int>(sig);
      }
      if (semi != std::string_view::npos) {
        uint64_t addr = 0;
        if (parse_hex_u64(args.substr(semi + 1), addr)) {
          req.addr = addr;
        }
      }
    } else {
      if (semi == std::string_view::npos) {
        uint64_t addr = 0;
        if (parse_hex_u64(args, addr)) {
          req.addr = addr;
        }
      } else {
        uint64_t addr = 0;
        if (parse_hex_u64(args.substr(semi + 1), addr)) {
          req.addr = addr;
        }
      }
    }
  }

  auto result = target_.run.resume(req);
  finish_resume(result, false);
}

void server::handle_reverse(bool step) {
  auto caps = run_caps();
  if ((step && !caps.reverse_step) || (!step && !caps.reverse_continue)) {
    send_packet("");
    return;
  }
  auto result = target_.run.resume(step ? resume_request::reverse_step() : resume_request::reverse_cont());
  finish_resume(result, true);
}

void server::finish_resume(const resume_result& result, bool optional_feature) {
  if (result.status != target_status::ok) {
    send_status_error(result.status, optional_feature);
    return;
  }

  if (non_stop_.enabled) {
    if (result.state == resume_result::state::running) {
      exec_state_ = exec_state::running;
      send_packet("OK");
      return;
    }
    exec_state_ = exec_state::halted;
    enqueue_stop(result.stop);
    send_packet("OK");
    maybe_send_stop_notification();
    return;
  }

  if (result.state == resume_result::state::running) {
    exec_state_ = exec_state::running;
    return;
  }

  exec_state_ = exec_state::halted;
  if (result.state == resume_result::state::exited || result.stop.kind == stop_kind::exited) {
    send_exit_reply(result.stop);
    return;
  }

  send_stop_reply(result.stop);
}

void server::handle_read_all_registers() {
  std::string out;
  for (int reg = 0; reg < arch_.reg_count; ++reg) {
    size_t size = target_.regs.reg_size(reg);
    if (size == 0) {
      continue;
    }

    std::vector<std::byte> buffer(size);
    auto status = target_.regs.read_reg(reg, buffer);
    if (status != target_status::ok) {
      out.append(size * 2, 'x');
      continue;
    }

    if (arch_.swap_register_endianness) {
      std::reverse(buffer.begin(), buffer.end());
    }
    out += rsp::encode_hex(buffer);
  }

  send_packet(out);
}

void server::handle_write_all_registers(std::string_view args) {
  size_t total_bytes = 0;
  for (int reg = 0; reg < arch_.reg_count; ++reg) {
    total_bytes += target_.regs.reg_size(reg);
  }

  if (args.size() != total_bytes * 2) {
    send_error(0x16);
    return;
  }

  size_t offset = 0;
  for (int reg = 0; reg < arch_.reg_count; ++reg) {
    size_t size = target_.regs.reg_size(reg);
    if (size == 0) {
      continue;
    }

    std::vector<std::byte> buffer(size);
    if (!rsp::decode_hex(args.substr(offset, size * 2), buffer)) {
      send_error(0x16);
      return;
    }

    if (arch_.swap_register_endianness) {
      std::reverse(buffer.begin(), buffer.end());
    }

    auto status = target_.regs.write_reg(reg, buffer);
    if (status != target_status::ok) {
      send_status_error(status, false);
      return;
    }

    offset += size * 2;
  }

  send_packet("OK");
}

void server::handle_read_register(std::string_view args) {
  uint64_t regno = 0;
  if (!parse_hex_u64(args, regno)) {
    send_error(0x16);
    return;
  }

  if (regno >= static_cast<uint64_t>(arch_.reg_count)) {
    send_error(0x16);
    return;
  }

  size_t size = target_.regs.reg_size(static_cast<int>(regno));
  if (size == 0) {
    send_error(0x16);
    return;
  }

  std::vector<std::byte> buffer(size);
  auto status = target_.regs.read_reg(static_cast<int>(regno), buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  if (arch_.swap_register_endianness) {
    std::reverse(buffer.begin(), buffer.end());
  }

  send_packet(rsp::encode_hex(buffer));
}

void server::handle_write_register(std::string_view args) {
  auto eq = args.find('=');
  if (eq == std::string_view::npos) {
    send_error(0x16);
    return;
  }

  uint64_t regno = 0;
  if (!parse_hex_u64(args.substr(0, eq), regno)) {
    send_error(0x16);
    return;
  }

  if (regno >= static_cast<uint64_t>(arch_.reg_count)) {
    send_error(0x16);
    return;
  }

  size_t size = target_.regs.reg_size(static_cast<int>(regno));
  auto hex = args.substr(eq + 1);
  if (size == 0 || hex.size() != size * 2) {
    send_error(0x16);
    return;
  }

  std::vector<std::byte> buffer(size);
  if (!rsp::decode_hex(hex, buffer)) {
    send_error(0x16);
    return;
  }

  if (arch_.swap_register_endianness) {
    std::reverse(buffer.begin(), buffer.end());
  }

  auto status = target_.regs.write_reg(static_cast<int>(regno), buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet("OK");
}

void server::handle_register_info(std::string_view args) {
  if (!target_.reg_info) {
    send_packet("E45");
    return;
  }

  uint64_t regno = 0;
  if (args.empty() || !parse_hex_u64(args, regno)) {
    send_error(0x16);
    return;
  }

  if (arch_.reg_count > 0 && regno >= static_cast<uint64_t>(arch_.reg_count)) {
    send_packet("E45");
    return;
  }

  auto info = target_.reg_info->get_register_info(static_cast<int>(regno));
  if (!info) {
    send_packet("E45");
    return;
  }

  auto reg_size = target_.regs.reg_size(static_cast<int>(regno));
  int bitsize = info->bitsize > 0 ? info->bitsize : static_cast<int>(reg_size * 8);
  if (bitsize <= 0) {
    send_error(0x16);
    return;
  }

  size_t offset = 0;
  if (info->offset) {
    offset = *info->offset;
  } else {
    for (int idx = 0; idx < static_cast<int>(regno); ++idx) {
      offset += target_.regs.reg_size(idx);
    }
  }

  std::string response;
  response.reserve(128);
  response += "name:";
  response += info->name;
  response += ";";
  if (info->alt_name && !info->alt_name->empty()) {
    response += "alt-name:";
    response += *info->alt_name;
    response += ";";
  }
  response += "bitsize:";
  response += std::to_string(bitsize);
  response += ";";
  response += "offset:";
  response += std::to_string(offset);
  response += ";";
  response += "encoding:";
  response += info->encoding.empty() ? "uint" : info->encoding;
  response += ";";
  response += "format:";
  response += info->format.empty() ? "hex" : info->format;
  response += ";";
  if (info->set && !info->set->empty()) {
    response += "set:";
    response += *info->set;
    response += ";";
  }
  if (info->gcc_regnum) {
    response += "gcc:";
    response += std::to_string(*info->gcc_regnum);
    response += ";";
  }
  if (info->dwarf_regnum) {
    response += "dwarf:";
    response += std::to_string(*info->dwarf_regnum);
    response += ";";
  }
  if (info->generic && !info->generic->empty()) {
    response += "generic:";
    response += *info->generic;
    response += ";";
  }
  if (!info->container_regs.empty()) {
    response += "container-regs:";
    for (size_t i = 0; i < info->container_regs.size(); ++i) {
      if (i > 0) {
        response.push_back(',');
      }
      response += hex_u64(static_cast<uint64_t>(info->container_regs[i]));
    }
    response += ";";
  }
  if (!info->invalidate_regs.empty()) {
    response += "invalidate-regs:";
    for (size_t i = 0; i < info->invalidate_regs.size(); ++i) {
      if (i > 0) {
        response.push_back(',');
      }
      response += hex_u64(static_cast<uint64_t>(info->invalidate_regs[i]));
    }
    response += ";";
  }

  send_packet(response);
}

void server::handle_read_memory(std::string_view args) {
  auto comma = args.find(',');
  if (comma == std::string_view::npos) {
    send_error(0x16);
    return;
  }

  uint64_t addr = 0;
  uint64_t len = 0;
  if (!parse_hex_u64(args.substr(0, comma), addr) || !parse_hex_u64(args.substr(comma + 1), len)) {
    send_error(0x16);
    return;
  }

  len = std::min<uint64_t>(len, k_max_memory_read);
  std::vector<std::byte> buffer(static_cast<size_t>(len));
  auto status = target_.mem.read_mem(addr, buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet(rsp::encode_hex(buffer));
}

void server::handle_read_binary_memory(std::string_view args) {
  auto comma = args.find(',');
  if (comma == std::string_view::npos) {
    send_error(0x16);
    return;
  }

  uint64_t addr = 0;
  uint64_t len = 0;
  if (!parse_hex_u64(args.substr(0, comma), addr) || !parse_hex_u64(args.substr(comma + 1), len)) {
    send_error(0x16);
    return;
  }

  len = std::min<uint64_t>(len, k_max_memory_read);
  std::vector<std::byte> buffer(static_cast<size_t>(len));
  auto status = target_.mem.read_mem(addr, buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet(rsp::escape_binary(std::span<const std::byte>(buffer.data(), buffer.size())));
}

void server::handle_write_memory(std::string_view args) {
  auto colon = args.find(':');
  auto comma = args.find(',');
  if (colon == std::string_view::npos || comma == std::string_view::npos || comma > colon) {
    send_error(0x16);
    return;
  }

  uint64_t addr = 0;
  uint64_t len = 0;
  if (!parse_hex_u64(args.substr(0, comma), addr) || !parse_hex_u64(args.substr(comma + 1, colon - comma - 1), len)) {
    send_error(0x16);
    return;
  }

  auto hex = args.substr(colon + 1);
  if (hex.size() != len * 2) {
    send_error(0x16);
    return;
  }

  std::vector<std::byte> buffer(static_cast<size_t>(len));
  if (!rsp::decode_hex(hex, buffer)) {
    send_error(0x16);
    return;
  }

  auto status = target_.mem.write_mem(addr, buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet("OK");
}

void server::handle_write_binary_memory(std::string_view args) {
  auto colon = args.find(':');
  auto comma = args.find(',');
  if (colon == std::string_view::npos || comma == std::string_view::npos || comma > colon) {
    send_error(0x16);
    return;
  }

  uint64_t addr = 0;
  uint64_t len = 0;
  if (!parse_hex_u64(args.substr(0, comma), addr) || !parse_hex_u64(args.substr(comma + 1, colon - comma - 1), len)) {
    send_error(0x16);
    return;
  }

  std::string data(args.substr(colon + 1));
  auto actual = rsp::unescape_binary(data);
  if (actual != len) {
    send_error(0x16);
    return;
  }

  std::vector<std::byte> buffer(data.size());
  std::memcpy(buffer.data(), data.data(), data.size());

  auto status = target_.mem.write_mem(addr, buffer);
  if (status != target_status::ok) {
    send_status_error(status, false);
    return;
  }

  send_packet("OK");
}

void server::handle_insert_breakpoint(std::string_view args) {
  if (!target_.breakpoints) {
    send_packet("");
    return;
  }

  breakpoint_parse_result parsed;
  if (!parse_breakpoint_packet(args, parsed)) {
    send_error(0x16);
    return;
  }

  auto type = parse_breakpoint_type(parsed.type);
  if (!type) {
    send_packet("");
    return;
  }
  if (parsed.kind > std::numeric_limits<uint32_t>::max()) {
    send_error(0x16);
    return;
  }

  auto caps = breakpoint_caps();
  if (!parsed.suffixes.conditions.empty() && !caps.supports_conditional) {
    send_packet("");
    return;
  }
  if (parsed.suffixes.commands && !caps.supports_commands) {
    send_packet("");
    return;
  }
  breakpoint_request request;
  request.spec = {*type, parsed.addr, static_cast<uint32_t>(parsed.kind)};
  if (caps.supports_thread_suffix && parsed.suffixes.thread_id) {
    request.thread_id = parsed.suffixes.thread_id;
    if (target_.threads) {
      target_.threads->set_current_thread(*parsed.suffixes.thread_id);
    }
  }
  request.conditions = std::move(parsed.suffixes.conditions);
  request.commands = std::move(parsed.suffixes.commands);

  auto status = target_.breakpoints->set_breakpoint(request);
  if (status == target_status::unsupported) {
    send_packet("");
    return;
  }
  send_status_error(status, false);
}

void server::handle_remove_breakpoint(std::string_view args) {
  if (!target_.breakpoints) {
    send_packet("");
    return;
  }

  breakpoint_parse_result parsed;
  if (!parse_breakpoint_packet(args, parsed)) {
    send_error(0x16);
    return;
  }

  auto type = parse_breakpoint_type(parsed.type);
  if (!type) {
    send_packet("");
    return;
  }
  if (parsed.kind > std::numeric_limits<uint32_t>::max()) {
    send_error(0x16);
    return;
  }

  auto caps = breakpoint_caps();
  if (!parsed.suffixes.conditions.empty() && !caps.supports_conditional) {
    send_packet("");
    return;
  }
  if (parsed.suffixes.commands && !caps.supports_commands) {
    send_packet("");
    return;
  }
  breakpoint_request request;
  request.spec = {*type, parsed.addr, static_cast<uint32_t>(parsed.kind)};
  if (caps.supports_thread_suffix && parsed.suffixes.thread_id) {
    request.thread_id = parsed.suffixes.thread_id;
    if (target_.threads) {
      target_.threads->set_current_thread(*parsed.suffixes.thread_id);
    }
  }
  request.conditions = std::move(parsed.suffixes.conditions);
  request.commands = std::move(parsed.suffixes.commands);

  auto status = target_.breakpoints->remove_breakpoint(request);
  if (status == target_status::unsupported) {
    send_packet("");
    return;
  }
  send_status_error(status, false);
}

void server::handle_set_thread(std::string_view args) {
  if (args.size() < 2) {
    send_error(0x16);
    return;
  }

  auto thread_str = args.substr(1);
  std::optional<uint64_t> tid;
  if (!parse_thread_token(thread_str, tid)) {
    send_error(0x16);
    return;
  }

  if (target_.threads && tid) {
    target_.threads->set_current_thread(*tid);
  }

  send_packet("OK");
}

void server::handle_thread_alive(std::string_view args) {
  uint64_t tid = 0;
  if (!parse_hex_u64(args, tid)) {
    send_error(0x16);
    return;
  }

  if (target_.threads) {
    auto ids = target_.threads->thread_ids();
    if (std::find(ids.begin(), ids.end(), tid) == ids.end()) {
      send_error(0x16);
      return;
    }
  }

  send_packet("OK");
}

void server::handle_halt_reason() {
  if (last_stop_) {
    send_stop_reply(*last_stop_);
    return;
  }

  send_stop_reply(stop_reason{stop_kind::signal, 5});
}

void server::handle_detach() {
  send_packet("OK");
  transport_->disconnect();
  exec_state_ = exec_state::halted;
  set_attached_state(attached_state::unknown);
}

void server::handle_extended_mode() {
  extended_mode_ = true;
  send_packet("OK");
}

void server::handle_j_packet(std::string_view payload) {
  if (payload.rfind("jThreadsInfo", 0) == 0) {
    handle_threads_info();
    return;
  }

  if (payload.rfind("jThreadExtendedInfo:", 0) == 0) {
    handle_thread_extended_info(payload.substr(std::string_view("jThreadExtendedInfo:").size()));
    return;
  }

  if (payload.rfind("jGetLoadedDynamicLibrariesInfos", 0) == 0) {
    auto pos = payload.find(':');
    std::string_view args;
    if (pos != std::string_view::npos) {
      args = payload.substr(pos + 1);
    }
    handle_loaded_dynamic_libraries_infos(args);
    return;
  }

  send_packet("");
}

void server::handle_threads_info() {
  if (!target_.threads) {
    send_packet("");
    return;
  }

  auto ids = thread_ids();
  std::string json;
  json.reserve(64 + ids.size() * 32);
  json.push_back('[');
  for (size_t i = 0; i < ids.size(); ++i) {
    if (i > 0) {
      json.push_back(',');
    }
    json.push_back('{');
    json += "\"tid\":";
    json += std::to_string(ids[i]);

    std::optional<stop_reason> reason;
    if (target_.threads) {
      reason = target_.threads->thread_stop_reason(ids[i]);
    }
    if (!reason && last_stop_ && (!last_stop_->thread_id || *last_stop_->thread_id == ids[i])) {
      reason = last_stop_;
    }
    if (reason) {
      json += ",\"reason\":\"";
      json += stop_reason_label(reason->kind);
      json += "\"";
      if (reason->signal > 0) {
        json += ",\"signal\":";
        json += std::to_string(reason->signal);
      }
    }

    json.push_back('}');
  }
  json.push_back(']');

  auto escaped = rsp::escape_binary(as_bytes(json));
  send_packet(escaped);
}

void server::handle_thread_extended_info(std::string_view args) {
  if (!target_.threads) {
    send_packet("");
    return;
  }

  std::string request(args);
  rsp::unescape_binary(request);
  auto tid = parse_json_thread_id(request);
  if (!tid) {
    send_error(0x16);
    return;
  }

  auto ids = thread_ids();
  if (!ids.empty() && std::find(ids.begin(), ids.end(), *tid) == ids.end()) {
    send_error(0x16);
    return;
  }

  std::string json;
  json.reserve(64);
  json.push_back('{');
  json += "\"thread\":";
  json += std::to_string(*tid);

  if (auto name = target_.threads->thread_name(*tid)) {
    json += ",\"name\":\"";
    json += escape_json_string(*name);
    json += "\"";
  }

  if (auto reason = target_.threads->thread_stop_reason(*tid)) {
    json += ",\"reason\":\"";
    json += stop_reason_label(reason->kind);
    json += "\"";
    if (reason->signal > 0) {
      json += ",\"signal\":";
      json += std::to_string(reason->signal);
    }
  }

  json.push_back('}');

  auto escaped = rsp::escape_binary(as_bytes(json));
  send_packet(escaped);
}

void server::handle_loaded_dynamic_libraries_infos(std::string_view args) {
  if (!target_.lldb) {
    send_packet("");
    return;
  }

  if (args.empty()) {
    send_packet("OK");
    return;
  }

  std::string request(args);
  rsp::unescape_binary(request);

  lldb::loaded_libraries_request parsed{};
  bool report_load_commands = true;
  if (parse_json_bool(request, "report_load_commands", report_load_commands)) {
    parsed.report_load_commands = report_load_commands;
  }

  bool fetch_all = false;
  if (parse_json_bool(request, "fetch_all_solibs", fetch_all) && fetch_all) {
    parsed.kind = lldb::loaded_libraries_request::kind::all;
  }

  std::vector<uint64_t> addresses;
  if (parse_json_u64_list(request, "solib_addresses", addresses)) {
    parsed.kind = lldb::loaded_libraries_request::kind::addresses;
    parsed.addresses = std::move(addresses);
  }

  auto image_count = parse_json_u64(request, "image_count");
  auto image_list_address = parse_json_u64(request, "image_list_address");
  if (image_count && image_list_address) {
    parsed.kind = lldb::loaded_libraries_request::kind::image_list;
    parsed.image_count = *image_count;
    parsed.image_list_address = *image_list_address;
  }

  auto payload = target_.lldb->loaded_libraries_json(parsed);
  if (!payload) {
    send_packet("");
    return;
  }

  auto escaped = rsp::escape_binary(as_bytes(*payload));
  send_packet(escaped);
}

void server::handle_shlib_info_addr() {
  if (!target_.shlib) {
    send_packet("");
    return;
  }

  auto info = target_.shlib->get_shlib_info();
  if (!info || !info->info_addr) {
    send_packet("");
    return;
  }

  size_t addr_size = 0;
  if (target_.host) {
    if (auto host = target_.host->get_host_info()) {
      if (host->ptr_size > 0) {
        addr_size = static_cast<size_t>(host->ptr_size);
      }
    }
  }
  if (addr_size == 0 && arch_.pc_reg_num >= 0) {
    addr_size = target_.regs.reg_size(arch_.pc_reg_num);
  }
  if (addr_size == 0 || addr_size > sizeof(uint64_t)) {
    addr_size = sizeof(uint64_t);
  }

  std::vector<std::byte> buffer(addr_size);
  uint64_t addr = *info->info_addr;
  for (size_t i = 0; i < addr_size; ++i) {
    size_t shift = (addr_size - 1 - i) * 8;
    buffer[i] = std::byte(static_cast<uint8_t>((addr >> shift) & 0xff));
  }

  send_packet(rsp::encode_hex(buffer));
}

void server::handle_offsets() {
  if (!target_.offsets) {
    send_packet("");
    return;
  }

  auto info = target_.offsets->get_offsets_info();
  if (!info) {
    send_packet("");
    return;
  }

  std::string response;
  switch (info->kind) {
  case offsets_kind::section:
    if (!info->data) {
      send_packet("");
      return;
    }
    response = "Text=" + hex_u64(info->text) + ";Data=" + hex_u64(*info->data);
    if (info->bss) {
      response += ";Bss=" + hex_u64(*info->bss);
    }
    break;
  case offsets_kind::segment:
    if (info->bss) {
      send_packet("");
      return;
    }
    response = "TextSeg=" + hex_u64(info->text);
    if (info->data) {
      response += ";DataSeg=" + hex_u64(*info->data);
    }
    break;
  default:
    send_packet("");
    return;
  }

  send_packet(response);
}

void server::handle_xfer(std::string_view args) {
  constexpr std::string_view k_features_prefix = "features:read:";
  if (args.rfind(k_features_prefix, 0) == 0) {
    auto rest = args.substr(k_features_prefix.size());
    auto annex_end = rest.find(':');
    if (annex_end == std::string_view::npos) {
      send_error(0x01);
      return;
    }
    auto annex = rest.substr(0, annex_end);
    auto range = rest.substr(annex_end + 1);
    auto resolved_annex = annex.empty() ? std::string_view("target.xml") : annex;
    if (resolved_annex != "target.xml") {
      send_packet("");
      return;
    }
    if (arch_.target_xml.empty()) {
      send_error(0x01);
      return;
    }

    auto comma = range.find(',');
    if (comma == std::string_view::npos) {
      send_error(0x01);
      return;
    }

    uint64_t offset = 0;
    uint64_t length = 0;
    if (!parse_hex_u64(range.substr(0, comma), offset) || !parse_hex_u64(range.substr(comma + 1), length)) {
      send_error(0x01);
      return;
    }

    if (offset >= arch_.target_xml.size()) {
      send_packet("l");
      return;
    }

    size_t available = arch_.target_xml.size() - static_cast<size_t>(offset);
    size_t to_send = static_cast<size_t>(std::min<uint64_t>(length, available));

    std::string response;
    response.reserve(to_send + 1);
    response.push_back(offset + to_send >= arch_.target_xml.size() ? 'l' : 'm');
    response.append(arch_.target_xml.data() + offset, to_send);
    send_packet(response);
    return;
  }

  constexpr std::string_view k_memory_map_prefix = "memory-map:read::";
  if (args.rfind(k_memory_map_prefix, 0) == 0) {
    if (!target_.memory_layout || !target_.memory_layout->has_memory_map()) {
      send_packet("");
      return;
    }

    auto range = args.substr(k_memory_map_prefix.size());
    auto comma = range.find(',');
    if (comma == std::string_view::npos) {
      send_error(0x01);
      return;
    }

    uint64_t offset = 0;
    uint64_t length = 0;
    if (!parse_hex_u64(range.substr(0, comma), offset) || !parse_hex_u64(range.substr(comma + 1), length)) {
      send_error(0x01);
      return;
    }

    auto xml = build_memory_map_xml(target_.memory_layout->memory_map());
    if (offset >= xml.size()) {
      send_packet("l");
      return;
    }

    size_t available = xml.size() - static_cast<size_t>(offset);
    size_t to_send = static_cast<size_t>(std::min<uint64_t>(length, available));
    std::string response;
    response.reserve(to_send + 1);
    response.push_back(offset + to_send >= xml.size() ? 'l' : 'm');
    response.append(xml.data() + offset, to_send);
    send_packet(response);
    return;
  }

  constexpr std::string_view k_libraries_prefix = "libraries:read::";
  if (args.rfind(k_libraries_prefix, 0) == 0) {
    if (!target_.libraries) {
      send_packet("");
      return;
    }

    auto range = args.substr(k_libraries_prefix.size());
    auto comma = range.find(',');
    if (comma == std::string_view::npos) {
      send_error(0x01);
      return;
    }

    uint64_t offset = 0;
    uint64_t length = 0;
    if (!parse_hex_u64(range.substr(0, comma), offset) || !parse_hex_u64(range.substr(comma + 1), length)) {
      send_error(0x01);
      return;
    }

    auto xml = build_library_list_xml(target_.libraries->libraries());
    if (offset >= xml.size()) {
      send_packet("l");
      return;
    }

    size_t available = xml.size() - static_cast<size_t>(offset);
    size_t to_send = static_cast<size_t>(std::min<uint64_t>(length, available));
    std::string response;
    response.reserve(to_send + 1);
    response.push_back(offset + to_send >= xml.size() ? 'l' : 'm');
    response.append(xml.data() + offset, to_send);
    send_packet(response);
    return;
  }

  send_packet("");
}

void server::handle_host_info() {
  if (!target_.host) {
    send_packet("");
    return;
  }

  auto info = target_.host->get_host_info();
  if (!info) {
    send_packet("");
    return;
  }

  std::string response;
  response.reserve(128);
  response += "triple:" + hex_encode_string(info->triple) + ";";
  response += "ptrsize:" + std::to_string(info->ptr_size) + ";";
  response += "endian:" + info->endian + ";";
  response += "hostname:" + hex_encode_string(info->hostname) + ";";

  if (info->os_version) {
    response += "os_version:" + *info->os_version + ";";
  }
  if (info->os_build) {
    response += "os_build:" + hex_encode_string(*info->os_build) + ";";
  }
  if (info->os_kernel) {
    response += "os_kernel:" + hex_encode_string(*info->os_kernel) + ";";
  }
  if (info->addressing_bits) {
    response += "addressing_bits:" + std::to_string(*info->addressing_bits) + ";";
  }

  send_packet(response);
}

void server::handle_process_info() {
  if (!target_.process) {
    send_packet("");
    return;
  }

  auto info = target_.process->get_process_info();
  if (!info) {
    send_error(0x0e);
    return;
  }

  std::string response;
  response.reserve(128);
  response += "pid:" + hex_u64(static_cast<uint64_t>(info->pid)) + ";";
  response += "triple:" + hex_encode_string(info->triple) + ";";
  response += "endian:" + info->endian + ";";
  response += "ptrsize:" + std::to_string(info->ptr_size) + ";";
  response += "ostype:" + info->ostype + ";";
  if (target_.lldb) {
    if (auto extras = target_.lldb->process_info_extras()) {
      for (const auto& pair : *extras) {
        if (pair.key.empty()) {
          continue;
        }
        response += pair.key;
        response += ":";
        switch (pair.encoding) {
        case lldb::kv_encoding::raw:
          response += pair.value;
          break;
        case lldb::kv_encoding::hex_string:
          response += hex_encode_string(pair.value);
          break;
        case lldb::kv_encoding::hex_u64:
          response += hex_u64(pair.u64_value);
          break;
        case lldb::kv_encoding::dec_u64:
          response += std::to_string(pair.u64_value);
          break;
        }
        response += ";";
      }
    }
  }
  send_packet(response);
}

void server::handle_memory_region_info(std::string_view addr_str) {
  if (!target_.memory_layout) {
    send_packet("");
    return;
  }

  uint64_t addr = 0;
  if (!parse_hex_u64(addr_str, addr)) {
    send_error(0x16);
    return;
  }

  std::optional<memory_region_info> info;
  if (target_.memory_layout->has_region_info()) {
    info = target_.memory_layout->region_info(addr);
  }

  if (!info && target_.memory_layout->has_memory_map()) {
    auto regions = target_.memory_layout->memory_map();
    std::optional<memory_region_info> mapped = region_info_from_map(regions, addr);
    uint64_t next_start = std::numeric_limits<uint64_t>::max();
    for (const auto& region : regions) {
      auto start = region.start;
      if (start > addr && start < next_start) {
        next_start = start;
      }
    }
    if (mapped) {
      info = std::move(mapped);
    } else {
      uint64_t end_exclusive = next_start;
      if (end_exclusive == std::numeric_limits<uint64_t>::max()) {
        end_exclusive = address_space_end(target_, arch_);
      }
      if (end_exclusive <= addr) {
        end_exclusive = std::numeric_limits<uint64_t>::max();
      }
      if (end_exclusive <= addr) {
        send_error(0x0e);
        return;
      }
      info = unmapped_region_info(addr, end_exclusive - addr);
    }
  }

  if (!info) {
    send_error(0x0e);
    return;
  }

  std::string response;
  response.reserve(128);
  response += "start:" + hex_u64(info->start, sizeof(uint64_t) * 2) + ";";
  response += "size:" + hex_u64(info->size, sizeof(uint64_t) * 2) + ";";
  if (info->mapped) {
    auto perms = perms_to_string(info->perms);
    if (perms.empty()) {
      perms = "rwx";
    }
    response += "permissions:" + perms + ";";
    if (info->name && !info->name->empty()) {
      response += "name:" + hex_encode_string(*info->name) + ";";
    }
    if (!info->types.empty()) {
      response += "type:" + join_types(info->types) + ";";
    }
  }
  send_packet(response);
}

bool server::process_control_enabled() const {
  return extended_mode_ && target_.process_control.has_value();
}

const process_control_view* server::process_control() const {
  if (!process_control_enabled()) {
    return nullptr;
  }
  return &*target_.process_control;
}

void server::set_attached_state(attached_state state) {
  attached_state_ = state;
  last_library_generation_.reset();
}

void server::set_attached_state_if_ok(attached_state state, target_status status) {
  if (status == target_status::ok) {
    set_attached_state(state);
  }
}

void server::send_ack() { transport_->write(as_bytes(std::string_view{&rsp::ack_char, 1})); }

void server::send_nack() { transport_->write(as_bytes(std::string_view{&rsp::nack_char, 1})); }

void server::send_packet(std::string_view payload) {
  auto packet = rsp::build_packet(payload);
  auto bytes = as_bytes(packet);

  size_t offset = 0;
  while (offset < bytes.size()) {
    auto written = transport_->write(bytes.subspan(offset));
    if (written <= 0) {
      transport_->disconnect();
      return;
    }
    offset += static_cast<size_t>(written);
  }
}

void server::send_notification(std::string_view payload) {
  auto packet = rsp::build_notification(payload);
  auto bytes = as_bytes(packet);

  size_t offset = 0;
  while (offset < bytes.size()) {
    auto written = transport_->write(bytes.subspan(offset));
    if (written <= 0) {
      transport_->disconnect();
      return;
    }
    offset += static_cast<size_t>(written);
  }
}

void server::send_error(uint8_t code) { send_packet("E" + hex_byte(code)); }

void server::send_status_error(target_status status, bool optional_feature) {
  if (status == target_status::ok) {
    send_packet("OK");
    return;
  }

  if (status == target_status::unsupported && optional_feature) {
    send_packet("");
    return;
  }

  send_error(error_code_for_status(status));
}

void server::send_stop_reply(const stop_reason& reason) {
  bool include_library = consume_library_change();
  auto response = build_stop_reply_payload(reason, include_library);
  last_stop_ = reason;
  send_packet(response);
}

void server::send_exit_reply(const stop_reason& reason) {
  auto response = build_stop_reply_payload(reason, false);
  last_stop_ = reason;
  send_packet(response);
}

std::string server::build_stop_reply_payload(const stop_reason& reason, bool include_library_key) const {
  if (reason.kind == stop_kind::exited) {
    int code = reason.exit_code;
    if (code < 0) {
      code = 0;
    }
    return "W" + hex_byte(static_cast<uint8_t>(code & 0xff));
  }

  int signal = reason.signal;
  if (signal <= 0 && reason.kind != stop_kind::signal) {
    signal = 5;
  }

  std::string response = "T" + hex_byte(static_cast<uint8_t>(signal & 0xff));

  switch (reason.kind) {
  case stop_kind::watch_write:
    response += "watch:" + hex_u64(reason.addr, sizeof(uint64_t) * 2) + ";";
    break;
  case stop_kind::watch_read:
    response += "rwatch:" + hex_u64(reason.addr, sizeof(uint64_t) * 2) + ";";
    break;
  case stop_kind::watch_access:
    response += "awatch:" + hex_u64(reason.addr, sizeof(uint64_t) * 2) + ";";
    break;
  case stop_kind::sw_break:
    if (supports_sw_break()) {
      response += "swbreak:;";
    }
    break;
  case stop_kind::hw_break:
    if (supports_hw_break()) {
      response += "hwbreak:;";
    }
    break;
  default:
    break;
  }

  if (reason.replay_log) {
    response += "replaylog:";
    response += *reason.replay_log == replay_log_boundary::begin ? "begin" : "end";
    response += ";";
  }

  uint64_t tid = reason.thread_id.value_or(current_thread_id().value_or(1));
  response += "thread:" + hex_u64(tid) + ";";

  if (include_library_key) {
    response += "library:;";
  }

  if (list_threads_in_stop_reply_ && target_.threads) {
    auto ids = thread_ids();
    if (!ids.empty()) {
      response += "threads:";
      for (size_t i = 0; i < ids.size(); ++i) {
        if (i > 0) {
          response.push_back(',');
        }
        response += hex_u64(ids[i]);
      }
      response += ";";

      response += "thread-pcs:";
      for (size_t i = 0; i < ids.size(); ++i) {
        if (i > 0) {
          response.push_back(',');
        }
        auto pc = target_.threads->thread_pc(ids[i]).value_or(0);
        response += hex_u64(pc);
      }
      response += ";";
    }
  }

  if (arch_.pc_reg_num >= 0) {
    size_t pc_size = target_.regs.reg_size(arch_.pc_reg_num);
    if (pc_size > 0) {
      std::vector<std::byte> buffer(pc_size);
      if (target_.regs.read_reg(arch_.pc_reg_num, buffer) == target_status::ok) {
        if (arch_.swap_register_endianness) {
          std::reverse(buffer.begin(), buffer.end());
        }
        response += hex_u64(static_cast<uint64_t>(arch_.pc_reg_num));
        response += ":";
        response += rsp::encode_hex(buffer);
        response += ";";
      }
    }
  }

  return response;
}

bool server::consume_library_change() {
  if (!target_.libraries) {
    return false;
  }
  auto generation = target_.libraries->generation();
  if (!generation) {
    return false;
  }
  if (!last_library_generation_ || *generation != *last_library_generation_) {
    last_library_generation_ = *generation;
    return true;
  }
  return false;
}

void server::enqueue_stop(stop_reason reason) {
  if (non_stop_.stop_signal_zero_pending) {
    reason.kind = stop_kind::signal;
    reason.signal = 0;
    non_stop_.stop_signal_zero_pending = false;
  }
  last_stop_ = reason;
  std::lock_guard<std::mutex> lock(non_stop_.mutex);
  non_stop_.pending_stops.push(std::move(reason));
}

void server::maybe_send_stop_notification() {
  if (!non_stop_.enabled || non_stop_.notification_in_flight) {
    return;
  }

  std::optional<stop_reason> reason;
  {
    std::lock_guard<std::mutex> lock(non_stop_.mutex);
    if (!non_stop_.pending_stops.empty()) {
      reason = std::move(non_stop_.pending_stops.front());
      non_stop_.pending_stops.pop();
    }
  }

  if (!reason) {
    return;
  }

  bool include_library = consume_library_change();
  auto payload = "Stop:" + build_stop_reply_payload(*reason, include_library);
  send_notification(payload);
  non_stop_.notification_in_flight = true;
}

std::optional<uint64_t> server::current_thread_id() const {
  if (target_.threads) {
    return target_.threads->current_thread();
  }
  return std::nullopt;
}

std::vector<uint64_t> server::thread_ids() const {
  if (target_.threads) {
    auto ids = target_.threads->thread_ids();
    if (!ids.empty()) {
      return ids;
    }
  }
  return {current_thread_id().value_or(1)};
}

run_capabilities server::run_caps() const {
  if (auto caps = target_.run.capabilities()) {
    return *caps;
  }
  return {};
}

breakpoint_capabilities server::breakpoint_caps() const {
  if (!target_.breakpoints) {
    return {};
  }
  if (auto caps = target_.breakpoints->capabilities()) {
    return *caps;
  }
  breakpoint_capabilities defaults;
  defaults.software = true;
  return defaults;
}

void server::reset_non_stop_state() {
  non_stop_.notification_in_flight = false;
  non_stop_.stop_signal_zero_pending = false;
  std::lock_guard<std::mutex> lock(non_stop_.mutex);
  while (!non_stop_.pending_stops.empty()) {
    non_stop_.pending_stops.pop();
  }
}

bool server::supports_sw_break() const { return breakpoint_caps().software; }

bool server::supports_hw_break() const { return breakpoint_caps().hardware; }

} // namespace gdbstub
