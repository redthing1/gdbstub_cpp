#include "gdbstub/server/server.hpp"

#include "gdbstub/server/detail.hpp"

namespace gdbstub {

using namespace server_detail;

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

} // namespace gdbstub
