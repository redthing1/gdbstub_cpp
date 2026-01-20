#include "gdbstub/server/detail.hpp"

#include <cctype>
#include <charconv>
#include <cstdio>
#include <limits>

#include "gdbstub/protocol/rsp_core.hpp"
#include "gdbstub/server/server.hpp"

namespace gdbstub::server_detail {

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

std::string hex_u64(uint64_t value, size_t width) {
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

} // namespace gdbstub::server_detail
