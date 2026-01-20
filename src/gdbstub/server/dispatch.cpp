#include "gdbstub/server/server.hpp"

#include "gdbstub/server/detail.hpp"

namespace gdbstub {

using namespace server_detail;

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

} // namespace gdbstub
