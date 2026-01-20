#pragma once

#include <concepts>
#include <memory>
#include <type_traits>
#include <utility>

#include "gdbstub/target/views.hpp"

namespace gdbstub {

namespace detail {

template <typename T>
constexpr bool always_false = false;

template <typename T>
concept regs_capability = requires(T& t, int regno, std::span<std::byte> out, std::span<const std::byte> in) {
  { t.reg_size(regno) } -> std::same_as<size_t>;
  { t.read_reg(regno, out) } -> std::same_as<target_status>;
  { t.write_reg(regno, in) } -> std::same_as<target_status>;
};

template <typename T>
concept mem_capability = requires(T& t, uint64_t addr, std::span<std::byte> out, std::span<const std::byte> in) {
  { t.read_mem(addr, out) } -> std::same_as<target_status>;
  { t.write_mem(addr, in) } -> std::same_as<target_status>;
};

template <typename T>
concept run_capability = requires(T& t, const resume_request& request) {
  { t.resume(request) } -> std::same_as<resume_result>;
};

template <typename T>
concept run_capabilities_capability = requires(T& t) {
  { t.capabilities() } -> std::same_as<run_capabilities>;
};

template <typename T>
concept run_interrupt = requires(T& t) {
  t.interrupt();
};

template <typename T>
concept run_poll_stop = requires(T& t) {
  { t.poll_stop() } -> std::same_as<std::optional<stop_reason>>;
};

template <typename T>
concept run_stop_notifier = requires(T& t, stop_notifier notifier) {
  t.set_stop_notifier(notifier);
};

template <typename T>
concept register_info_capability = requires(T& t, int regno) {
  { t.get_register_info(regno) } -> std::same_as<std::optional<register_info>>;
};

template <typename T>
concept breakpoints_capability = requires(T& t, const breakpoint_request& request) {
  { t.set_breakpoint(request) } -> std::same_as<target_status>;
  { t.remove_breakpoint(request) } -> std::same_as<target_status>;
};

template <typename T>
concept breakpoint_capabilities_capability = requires(T& t) {
  { t.capabilities() } -> std::same_as<breakpoint_capabilities>;
};

template <typename T>
concept memory_layout_region_capability = requires(T& t, uint64_t addr) {
  { t.region_info(addr) } -> std::same_as<std::optional<memory_region_info>>;
};

template <typename T>
concept memory_layout_map_capability = requires(T& t) {
  { t.memory_map() } -> std::same_as<std::vector<memory_region>>;
};

template <typename T>
concept memory_layout_capability = memory_layout_region_capability<T> || memory_layout_map_capability<T>;

template <typename T>
concept threads_capability = requires(T& t, uint64_t tid) {
  { t.thread_ids() } -> std::same_as<std::vector<uint64_t>>;
  { t.current_thread() } -> std::same_as<uint64_t>;
  { t.set_current_thread(tid) } -> std::same_as<target_status>;
  { t.thread_pc(tid) } -> std::same_as<std::optional<uint64_t>>;
  { t.thread_name(tid) } -> std::same_as<std::optional<std::string>>;
  { t.thread_stop_reason(tid) } -> std::same_as<std::optional<stop_reason>>;
};

template <typename T>
concept host_info_capability = requires(T& t) {
  { t.get_host_info() } -> std::same_as<std::optional<host_info>>;
};

template <typename T>
concept process_info_capability = requires(T& t) {
  { t.get_process_info() } -> std::same_as<std::optional<process_info>>;
};

template <typename T>
concept shlib_capability = requires(T& t) {
  { t.get_shlib_info() } -> std::same_as<std::optional<shlib_info>>;
};

template <typename T>
concept libraries_capability = requires(T& t) {
  { t.libraries() } -> std::same_as<std::vector<library_entry>>;
};

template <typename T>
concept libraries_generation_capability = requires(T& t) {
  { t.libraries_generation() } -> std::same_as<std::optional<uint64_t>>;
};

template <typename T>
concept lldb_process_info_extras_capability = requires(T& t) {
  { t.process_info_extras() } -> std::same_as<std::optional<std::vector<lldb::process_kv_pair>>>;
};

template <typename T>
concept lldb_loaded_libraries_capability = requires(T& t, const lldb::loaded_libraries_request& request) {
  { t.loaded_libraries_json(request) } -> std::same_as<std::optional<std::string>>;
};

template <typename T>
concept lldb_capability = lldb_process_info_extras_capability<T> || lldb_loaded_libraries_capability<T>;

template <typename T>
concept process_launch_capability = requires(T& t, const process_launch_request& request) {
  { t.launch(request) } -> std::same_as<std::optional<resume_result>>;
};

template <typename T>
concept process_attach_capability = requires(T& t, uint64_t pid) {
  { t.attach(pid) } -> std::same_as<std::optional<resume_result>>;
};

template <typename T>
concept process_kill_capability = requires(T& t, std::optional<uint64_t> pid) {
  { t.kill(pid) } -> std::same_as<target_status>;
};

template <typename T>
concept process_restart_capability = requires(T& t) {
  { t.restart() } -> std::same_as<std::optional<resume_result>>;
};

template <typename T>
concept process_control_capability = process_launch_capability<T> || process_attach_capability<T> ||
                                     process_kill_capability<T> || process_restart_capability<T>;

template <typename T>
concept offsets_capability = requires(T& t) {
  { t.get_offsets_info() } -> std::same_as<std::optional<offsets_info>>;
};

template <typename T>
regs_view make_regs_view(T& regs) {
  regs_view view;
  view.ctx = std::addressof(regs);
  view.reg_size_fn = [](void* ctx, int regno) -> size_t {
    return static_cast<T*>(ctx)->reg_size(regno);
  };
  view.read_reg_fn = [](void* ctx, int regno, std::span<std::byte> out) -> target_status {
    return static_cast<T*>(ctx)->read_reg(regno, out);
  };
  view.write_reg_fn = [](void* ctx, int regno, std::span<const std::byte> data) -> target_status {
    return static_cast<T*>(ctx)->write_reg(regno, data);
  };
  return view;
}

template <typename T>
mem_view make_mem_view(T& mem) {
  mem_view view;
  view.ctx = std::addressof(mem);
  view.read_mem_fn = [](void* ctx, uint64_t addr, std::span<std::byte> out) -> target_status {
    return static_cast<T*>(ctx)->read_mem(addr, out);
  };
  view.write_mem_fn = [](void* ctx, uint64_t addr, std::span<const std::byte> data) -> target_status {
    return static_cast<T*>(ctx)->write_mem(addr, data);
  };
  return view;
}

template <typename T>
run_view make_run_view(T& run) {
  run_view view;
  view.ctx = std::addressof(run);
  view.resume_fn = [](void* ctx, const resume_request& request) -> resume_result {
    return static_cast<T*>(ctx)->resume(request);
  };
  if constexpr (run_interrupt<T>) {
    view.interrupt_fn = [](void* ctx) { static_cast<T*>(ctx)->interrupt(); };
  }
  if constexpr (run_poll_stop<T>) {
    view.poll_stop_fn = [](void* ctx) -> std::optional<stop_reason> { return static_cast<T*>(ctx)->poll_stop(); };
  }
  if constexpr (run_stop_notifier<T>) {
    view.set_stop_notifier_fn = [](void* ctx, stop_notifier notifier) {
      static_cast<T*>(ctx)->set_stop_notifier(notifier);
    };
  }
  if constexpr (run_capabilities_capability<T>) {
    view.get_run_capabilities_fn = [](void* ctx) -> std::optional<run_capabilities> {
      return static_cast<T*>(ctx)->capabilities();
    };
  }
  return view;
}

template <typename T>
breakpoints_view make_breakpoints_view(T& breakpoints) {
  breakpoints_view view;
  view.ctx = std::addressof(breakpoints);
  view.set_breakpoint_fn = [](void* ctx, const breakpoint_request& request) -> target_status {
    return static_cast<T*>(ctx)->set_breakpoint(request);
  };
  view.remove_breakpoint_fn = [](void* ctx, const breakpoint_request& request) -> target_status {
    return static_cast<T*>(ctx)->remove_breakpoint(request);
  };
  if constexpr (breakpoint_capabilities_capability<T>) {
    view.get_breakpoint_capabilities_fn = [](void* ctx) -> std::optional<breakpoint_capabilities> {
      return static_cast<T*>(ctx)->capabilities();
    };
  }
  return view;
}

template <typename T>
memory_layout_view make_memory_layout_view(T& layout) {
  memory_layout_view view;
  view.ctx = std::addressof(layout);
  if constexpr (memory_layout_region_capability<T>) {
    view.region_info_fn = [](void* ctx, uint64_t addr) -> std::optional<memory_region_info> {
      return static_cast<T*>(ctx)->region_info(addr);
    };
  }
  if constexpr (memory_layout_map_capability<T>) {
    view.memory_map_fn = [](void* ctx) -> std::vector<memory_region> {
      return static_cast<T*>(ctx)->memory_map();
    };
  }
  return view;
}

template <typename T>
threads_view make_threads_view(T& threads) {
  threads_view view;
  view.ctx = std::addressof(threads);
  view.thread_ids_fn = [](void* ctx) -> std::vector<uint64_t> { return static_cast<T*>(ctx)->thread_ids(); };
  view.current_thread_fn = [](void* ctx) -> uint64_t { return static_cast<T*>(ctx)->current_thread(); };
  view.set_current_thread_fn = [](void* ctx, uint64_t tid) -> target_status {
    return static_cast<T*>(ctx)->set_current_thread(tid);
  };
  view.thread_pc_fn = [](void* ctx, uint64_t tid) -> std::optional<uint64_t> {
    return static_cast<T*>(ctx)->thread_pc(tid);
  };
  view.thread_name_fn = [](void* ctx, uint64_t tid) -> std::optional<std::string> {
    return static_cast<T*>(ctx)->thread_name(tid);
  };
  view.thread_stop_reason_fn = [](void* ctx, uint64_t tid) -> std::optional<stop_reason> {
    return static_cast<T*>(ctx)->thread_stop_reason(tid);
  };
  return view;
}

template <typename T>
host_info_view make_host_info_view(T& host) {
  host_info_view view;
  view.ctx = std::addressof(host);
  view.get_host_info_fn = [](void* ctx) -> std::optional<host_info> { return static_cast<T*>(ctx)->get_host_info(); };
  return view;
}

template <typename T>
process_info_view make_process_info_view(T& process) {
  process_info_view view;
  view.ctx = std::addressof(process);
  view.get_process_info_fn = [](void* ctx) -> std::optional<process_info> {
    return static_cast<T*>(ctx)->get_process_info();
  };
  return view;
}

template <typename T>
shlib_view make_shlib_view(T& shlib) {
  shlib_view view;
  view.ctx = std::addressof(shlib);
  view.get_shlib_info_fn = [](void* ctx) -> std::optional<shlib_info> { return static_cast<T*>(ctx)->get_shlib_info(); };
  return view;
}

template <typename T>
libraries_view make_libraries_view(T& libraries) {
  libraries_view view;
  view.ctx = std::addressof(libraries);
  view.get_libraries_fn = [](void* ctx) -> std::vector<library_entry> {
    return static_cast<T*>(ctx)->libraries();
  };
  if constexpr (libraries_generation_capability<T>) {
    view.generation_fn = [](void* ctx) -> std::optional<uint64_t> {
      return static_cast<T*>(ctx)->libraries_generation();
    };
  }
  return view;
}

template <typename T>
lldb::view make_lldb_view(T& lldb_ext) {
  lldb::view view;
  view.ctx = std::addressof(lldb_ext);
  if constexpr (lldb_process_info_extras_capability<T>) {
    view.process_info_extras_fn = [](void* ctx) -> std::optional<std::vector<lldb::process_kv_pair>> {
      return static_cast<T*>(ctx)->process_info_extras();
    };
  }
  if constexpr (lldb_loaded_libraries_capability<T>) {
    view.loaded_libraries_json_fn = [](void* ctx, const lldb::loaded_libraries_request& request)
        -> std::optional<std::string> { return static_cast<T*>(ctx)->loaded_libraries_json(request); };
  }
  return view;
}

template <typename T>
process_control_view make_process_control_view(T& control) {
  process_control_view view;
  view.ctx = std::addressof(control);
  if constexpr (process_launch_capability<T>) {
    view.launch_fn = [](void* ctx, const process_launch_request& request) -> std::optional<resume_result> {
      return static_cast<T*>(ctx)->launch(request);
    };
  }
  if constexpr (process_attach_capability<T>) {
    view.attach_fn = [](void* ctx, uint64_t pid) -> std::optional<resume_result> {
      return static_cast<T*>(ctx)->attach(pid);
    };
  }
  if constexpr (process_kill_capability<T>) {
    view.kill_fn = [](void* ctx, std::optional<uint64_t> pid) -> target_status {
      return static_cast<T*>(ctx)->kill(pid);
    };
  }
  if constexpr (process_restart_capability<T>) {
    view.restart_fn = [](void* ctx) -> std::optional<resume_result> {
      return static_cast<T*>(ctx)->restart();
    };
  }
  return view;
}

template <typename T>
offsets_view make_offsets_view(T& offsets) {
  offsets_view view;
  view.ctx = std::addressof(offsets);
  view.get_offsets_info_fn = [](void* ctx) -> std::optional<offsets_info> {
    return static_cast<T*>(ctx)->get_offsets_info();
  };
  return view;
}

template <typename T>
register_info_view make_register_info_view(T& reg_info) {
  register_info_view view;
  view.ctx = std::addressof(reg_info);
  view.get_register_info_fn = [](void* ctx, int regno) -> std::optional<register_info> {
    return static_cast<T*>(ctx)->get_register_info(regno);
  };
  return view;
}

template <typename T>
void assign_optional(target_view& view, T& obj) {
  static_assert(!regs_capability<T>, "Optional capability object implements register access; pass it as regs.");
  static_assert(!mem_capability<T>, "Optional capability object implements memory access; pass it as mem.");
  static_assert(!run_capability<T>, "Optional capability object implements run control; pass it as run.");
  constexpr int matches = breakpoints_capability<T> + threads_capability<T> + memory_layout_capability<T> +
                          host_info_capability<T> + process_info_capability<T> + shlib_capability<T> +
                          libraries_capability<T> + lldb_capability<T> +
                          process_control_capability<T> + offsets_capability<T> + register_info_capability<T>;
  static_assert(matches >= 1, "Optional capability object must implement at least one optional capability.");

  if constexpr (breakpoints_capability<T>) {
    view.breakpoints = make_breakpoints_view(obj);
  }
  if constexpr (threads_capability<T>) {
    view.threads = make_threads_view(obj);
  }
  if constexpr (memory_layout_capability<T>) {
    view.memory_layout = make_memory_layout_view(obj);
  }
  if constexpr (host_info_capability<T>) {
    view.host = make_host_info_view(obj);
  }
  if constexpr (process_info_capability<T>) {
    view.process = make_process_info_view(obj);
  }
  if constexpr (shlib_capability<T>) {
    view.shlib = make_shlib_view(obj);
  }
  if constexpr (libraries_capability<T>) {
    view.libraries = make_libraries_view(obj);
  }
  if constexpr (lldb_capability<T>) {
    view.lldb = make_lldb_view(obj);
  }
  if constexpr (process_control_capability<T>) {
    view.process_control = make_process_control_view(obj);
  }
  if constexpr (offsets_capability<T>) {
    view.offsets = make_offsets_view(obj);
  }
  if constexpr (register_info_capability<T>) {
    view.reg_info = make_register_info_view(obj);
  }
}

} // namespace detail

template <typename Regs, typename Mem, typename Run, typename... Opts>
target make_target(Regs& regs, Mem& mem, Run& run, Opts&... opts) {
  static_assert(detail::regs_capability<Regs>, "Regs capability requires reg_size/read_reg/write_reg.");
  static_assert(detail::mem_capability<Mem>, "Mem capability requires read_mem/write_mem.");
  static_assert(detail::run_capability<Run>, "Run capability requires resume.");

  constexpr int breakpoints_count = (0 + ... + detail::breakpoints_capability<Opts>);
  static_assert(breakpoints_count <= 1, "Breakpoints capability provided multiple times.");
  constexpr int threads_count = (0 + ... + detail::threads_capability<Opts>);
  static_assert(threads_count <= 1, "Threads capability provided multiple times.");
  constexpr int memory_layout_count = (0 + ... + detail::memory_layout_capability<Opts>);
  static_assert(memory_layout_count <= 1, "Memory layout capability provided multiple times.");
  constexpr int host_count = (0 + ... + detail::host_info_capability<Opts>);
  static_assert(host_count <= 1, "Host info capability provided multiple times.");
  constexpr int process_count = (0 + ... + detail::process_info_capability<Opts>);
  static_assert(process_count <= 1, "Process info capability provided multiple times.");
  constexpr int shlib_count = (0 + ... + detail::shlib_capability<Opts>);
  static_assert(shlib_count <= 1, "Shlib capability provided multiple times.");
  constexpr int libraries_count = (0 + ... + detail::libraries_capability<Opts>);
  static_assert(libraries_count <= 1, "Libraries capability provided multiple times.");
  constexpr int lldb_count = (0 + ... + detail::lldb_capability<Opts>);
  static_assert(lldb_count <= 1, "LLDB capability provided multiple times.");
  constexpr int process_control_count = (0 + ... + detail::process_control_capability<Opts>);
  static_assert(process_control_count <= 1, "Process control capability provided multiple times.");
  constexpr int offsets_count = (0 + ... + detail::offsets_capability<Opts>);
  static_assert(offsets_count <= 1, "Offsets capability provided multiple times.");
  constexpr int reg_info_count = (0 + ... + detail::register_info_capability<Opts>);
  static_assert(reg_info_count <= 1, "Register info capability provided multiple times.");

  target_view view;
  view.regs = detail::make_regs_view(regs);
  view.mem = detail::make_mem_view(mem);
  view.run = detail::make_run_view(run);

  (detail::assign_optional(view, opts), ...);
  return target(std::move(view));
}

} // namespace gdbstub
