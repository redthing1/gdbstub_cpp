#pragma once

#include <cstdint>
#include <optional>

namespace gdbstub {

enum class stop_kind {
  signal,
  sw_break,
  hw_break,
  watch_read,
  watch_write,
  watch_access,
  exited,
};

enum class replay_log_boundary { begin, end };

enum class resume_direction { forward, reverse };

struct address_range {
  // Range stepping treats this as [start, end).
  uint64_t start = 0;
  uint64_t end = 0;

  static address_range from(uint64_t start_value, uint64_t end_value) {
    return {start_value, end_value};
  }
};

enum class resume_action { cont, step, range_step };

enum class target_status { ok, fault, invalid, unsupported };

struct stop_reason {
  stop_kind kind = stop_kind::signal;
  int signal = 0;
  uint64_t addr = 0;
  int exit_code = 0;
  std::optional<uint64_t> thread_id;
  std::optional<replay_log_boundary> replay_log;
};

struct resume_request {
  resume_action action = resume_action::cont;
  resume_direction direction = resume_direction::forward;
  std::optional<uint64_t> addr;
  std::optional<int> signal;
  std::optional<address_range> range;

  static resume_request cont(std::optional<int> signal_value = std::nullopt,
                             std::optional<uint64_t> addr_value = std::nullopt) {
    resume_request req;
    req.action = resume_action::cont;
    req.signal = signal_value;
    req.addr = addr_value;
    return req;
  }

  static resume_request step(std::optional<int> signal_value = std::nullopt,
                             std::optional<uint64_t> addr_value = std::nullopt) {
    resume_request req;
    req.action = resume_action::step;
    req.signal = signal_value;
    req.addr = addr_value;
    return req;
  }

  static resume_request range_step(address_range range_value) {
    resume_request req;
    req.action = resume_action::range_step;
    req.range = range_value;
    return req;
  }

  static resume_request reverse_cont(std::optional<int> signal_value = std::nullopt,
                                     std::optional<uint64_t> addr_value = std::nullopt) {
    auto req = cont(signal_value, addr_value);
    req.direction = resume_direction::reverse;
    return req;
  }

  static resume_request reverse_step(std::optional<int> signal_value = std::nullopt,
                                     std::optional<uint64_t> addr_value = std::nullopt) {
    auto req = step(signal_value, addr_value);
    req.direction = resume_direction::reverse;
    return req;
  }
};

struct resume_result {
  enum class state { stopped, running, exited };
  state state = state::stopped;
  stop_reason stop;
  int exit_code = 0;
  target_status status = target_status::ok;
};

} // namespace gdbstub
