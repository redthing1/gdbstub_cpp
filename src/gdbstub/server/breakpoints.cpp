#include "gdbstub/server/server.hpp"

#include <limits>

#include "gdbstub/server/detail.hpp"

namespace gdbstub {

using namespace server_detail;

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

} // namespace gdbstub
