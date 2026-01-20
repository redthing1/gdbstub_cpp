#include "gdbstub/server/server.hpp"

#include <array>

#include "gdbstub/server/detail.hpp"

namespace gdbstub {

using namespace server_detail;

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

} // namespace gdbstub
