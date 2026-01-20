#include "gdbstub/server/server.hpp"

#include <algorithm>

#include "gdbstub/server/detail.hpp"

namespace gdbstub {

using namespace server_detail;

void server::handle_halt_reason() {
  if (last_stop_) {
    send_stop_reply(*last_stop_);
    return;
  }

  send_stop_reply(stop_reason{stop_kind::signal, 5});
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
