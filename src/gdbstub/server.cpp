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
    if (!region.permissions.empty()) {
      xml += " permissions=\"";
      xml += region.permissions;
      xml += "\"";
    }
    xml += "/>";
  }
  xml += "</memory-map>";
  return xml;
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

  bool processed = flush_pending_stop();
  processed = read_and_process(timeout) || processed;

  if (exec_state_ == exec_state::running) {
    if (auto stop = target_.run.poll_stop()) {
      send_stop_reply(*stop);
      exec_state_ = exec_state::halted;
      processed = true;
    }
  }

  return processed;
}

void server::notify_stop(stop_reason reason) {
  std::lock_guard<std::mutex> lock(stop_mutex_);
  pending_stops_.push(std::move(reason));
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

  std::optional<stop_reason> reason;
  {
    std::lock_guard<std::mutex> lock(stop_mutex_);
    if (!pending_stops_.empty()) {
      reason = std::move(pending_stops_.front());
      pending_stops_.pop();
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
    std::string features;
    features += "PacketSize=";
    features += hex_u64(k_max_packet_size);
    features += ";vContSupported+;QStartNoAckMode+";

    if (!arch_.target_xml.empty() && !arch_.xml_arch_name.empty()) {
      features += ";qXfer:features:read+;xmlRegisters=";
      features += arch_.xml_arch_name;
    }
    if (target_.breakpoints) {
      features += ";swbreak+";
    }
    if (target_.host) {
      features += ";qHostInfo+";
    }
    if (target_.process) {
      features += ";qProcessInfo+";
    }
    if (target_.memory_map) {
      features += ";qMemoryRegionInfo+;qXfer:memory-map:read+";
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

  if (name == "Attached") {
    send_packet("1");
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

  if (args.rfind("EnableErrorStrings", 0) == 0) {
    error_strings_enabled_ = true;
    send_packet("OK");
    return;
  }

  send_packet("");
}

void server::handle_v_packet(std::string_view args) {
  if (args == "Cont?") {
    send_packet("vCont;c;C;s;S");
    return;
  }

  if (args.rfind("Cont;", 0) != 0) {
    send_packet("");
    return;
  }

  auto actions = args.substr(5);
  uint64_t current_tid = current_thread_id().value_or(1);
  char selected = 0;
  std::optional<int> selected_signal;

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
        selected = action;
        if (!signal_str.empty()) {
          int sig = 0;
          uint64_t parsed = 0;
          if (parse_hex_u64(signal_str, parsed)) {
            sig = static_cast<int>(parsed);
          }
          selected_signal = sig > 0 ? std::optional<int>(sig) : std::nullopt;
        }
        break;
      }
    }

    if (next == std::string_view::npos) {
      break;
    }
    start = next + 1;
  }

  if (selected == 's' || selected == 'S') {
    resume_request req;
    req.action = resume_action::step;
    req.signal = selected_signal;
    auto result = target_.run.resume(req);
    if (result.state == resume_result::state::running) {
      exec_state_ = exec_state::running;
      return;
    }
    if (result.state == resume_result::state::exited) {
      send_exit_reply(result.stop);
      exec_state_ = exec_state::halted;
      return;
    }
    send_stop_reply(result.stop);
    exec_state_ = exec_state::halted;
    return;
  }

  if (selected == 'c' || selected == 'C') {
    resume_request req;
    req.action = resume_action::cont;
    req.signal = selected_signal;
    auto result = target_.run.resume(req);
    if (result.state == resume_result::state::running) {
      exec_state_ = exec_state::running;
      return;
    }
    if (result.state == resume_result::state::exited) {
      send_exit_reply(result.stop);
      exec_state_ = exec_state::halted;
      return;
    }
    send_stop_reply(result.stop);
    exec_state_ = exec_state::halted;
    return;
  }

  send_stop_reply(last_stop_.value_or(stop_reason{stop_kind::signal, 5}));
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

  auto first = args.find(',');
  auto second = args.find(',', first + 1);
  if (first == std::string_view::npos || second == std::string_view::npos) {
    send_error(0x16);
    return;
  }

  int parsed_type = 0;
  if (!parse_dec_int(args.substr(0, first), parsed_type)) {
    send_error(0x16);
    return;
  }
  auto type = parse_breakpoint_type(parsed_type);
  if (!type) {
    send_packet("");
    return;
  }

  uint64_t addr = 0;
  uint64_t kind = 0;
  if (!parse_hex_u64(args.substr(first + 1, second - first - 1), addr) ||
      !parse_hex_u64(args.substr(second + 1), kind)) {
    send_error(0x16);
    return;
  }
  if (kind > std::numeric_limits<uint32_t>::max()) {
    send_error(0x16);
    return;
  }

  breakpoint_spec request{*type, addr, static_cast<uint32_t>(kind)};
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

  auto first = args.find(',');
  auto second = args.find(',', first + 1);
  if (first == std::string_view::npos || second == std::string_view::npos) {
    send_error(0x16);
    return;
  }

  int parsed_type = 0;
  if (!parse_dec_int(args.substr(0, first), parsed_type)) {
    send_error(0x16);
    return;
  }
  auto type = parse_breakpoint_type(parsed_type);
  if (!type) {
    send_packet("");
    return;
  }

  uint64_t addr = 0;
  uint64_t kind = 0;
  if (!parse_hex_u64(args.substr(first + 1, second - first - 1), addr) ||
      !parse_hex_u64(args.substr(second + 1), kind)) {
    send_error(0x16);
    return;
  }
  if (kind > std::numeric_limits<uint32_t>::max()) {
    send_error(0x16);
    return;
  }

  breakpoint_spec request{*type, addr, static_cast<uint32_t>(kind)};
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
}

void server::handle_extended_mode() { send_packet("OK"); }

void server::handle_j_packet(std::string_view payload) {
  if (payload.rfind("jThreadsInfo", 0) == 0) {
    handle_threads_info();
    return;
  }

  if (payload.rfind("jThreadExtendedInfo:", 0) == 0) {
    handle_thread_extended_info(payload.substr(std::string_view("jThreadExtendedInfo:").size()));
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

void server::handle_xfer(std::string_view args) {
  if (args.rfind("features:read:target.xml:", 0) == 0) {
    if (arch_.target_xml.empty()) {
      send_error(0x01);
      return;
    }

    auto range = args.substr(25);
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
    if (!target_.memory_map) {
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

    auto xml = build_memory_map_xml(target_.memory_map->regions());
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
    response += "os_version:" + hex_encode_string(*info->os_version) + ";";
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
  send_packet(response);
}

void server::handle_memory_region_info(std::string_view addr_str) {
  if (!target_.memory_map) {
    send_packet("");
    return;
  }

  uint64_t addr = 0;
  if (!parse_hex_u64(addr_str, addr)) {
    send_error(0x16);
    return;
  }

  auto region = target_.memory_map->region_for(addr);
  if (!region) {
    send_error(0x0e);
    return;
  }

  std::string response;
  response.reserve(128);
  response += "start:" + hex_u64(region->start, sizeof(uint64_t) * 2) + ";";
  response += "size:" + hex_u64(region->size, sizeof(uint64_t) * 2) + ";";
  response += "permissions:" + region->permissions + ";";
  send_packet(response);
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
  if (reason.kind == stop_kind::exited) {
    send_exit_reply(reason);
    return;
  }

  int signal = reason.signal;
  if (reason.kind != stop_kind::signal || signal <= 0) {
    signal = 5;
  }

  std::string response = "T" + hex_byte(static_cast<uint8_t>(signal));

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
  default:
    break;
  }

  uint64_t tid = reason.thread_id.value_or(current_thread_id().value_or(1));
  response += "thread:" + hex_u64(tid) + ";";

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

  last_stop_ = reason;
  send_packet(response);
}

void server::send_exit_reply(const stop_reason& reason) {
  int code = reason.exit_code;
  if (code < 0) {
    code = 0;
  }
  send_packet("W" + hex_byte(static_cast<uint8_t>(code & 0xff)));
  last_stop_ = reason;
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

} // namespace gdbstub
