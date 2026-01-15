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

enum class resume_action { cont, step };

enum class target_status { ok, fault, invalid, unsupported };

struct stop_reason {
  stop_kind kind = stop_kind::signal;
  int signal = 0;
  uint64_t addr = 0;
  int exit_code = 0;
  std::optional<uint64_t> thread_id;
};

struct resume_request {
  resume_action action = resume_action::cont;
  std::optional<uint64_t> addr;
  std::optional<int> signal;
};

struct resume_result {
  enum class state { stopped, running, exited };
  state state = state::stopped;
  stop_reason stop;
  int exit_code = 0;
};

} // namespace gdbstub
