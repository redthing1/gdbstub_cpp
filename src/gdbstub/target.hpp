#pragma once

#include <concepts>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "gdbstub/rsp_types.hpp"

namespace gdbstub {

struct stop_notifier {
  void* ctx = nullptr;
  void (*notify)(void* ctx, const stop_reason& reason) = nullptr;

  void operator()(const stop_reason& reason) const {
    if (notify) {
      notify(ctx, reason);
    }
  }
};

enum class breakpoint_type {
  software = 0,
  hardware = 1,
  watch_write = 2,
  watch_read = 3,
  watch_access = 4,
};

struct breakpoint_spec {
  breakpoint_type type = breakpoint_type::software;
  uint64_t addr = 0;
  uint32_t length = 0;
};

struct memory_region {
  uint64_t start = 0;
  uint64_t size = 0;
  std::string permissions;
};

struct host_info {
  std::string triple;
  std::string endian;
  int ptr_size = 0;
  std::string hostname;
  std::optional<std::string> os_version;
  std::optional<std::string> os_build;
  std::optional<std::string> os_kernel;
  std::optional<int> addressing_bits;
};

struct process_info {
  int pid = 0;
  std::string triple;
  std::string endian;
  int ptr_size = 0;
  std::string ostype;
};

struct shlib_info {
  std::optional<uint64_t> info_addr;
};

struct register_info {
  std::string name;
  std::optional<std::string> alt_name;
  int bitsize = 0;
  std::optional<size_t> offset;
  std::string encoding;
  std::string format;
  std::optional<std::string> set;
  std::optional<int> gcc_regnum;
  std::optional<int> dwarf_regnum;
  std::optional<std::string> generic;
  std::vector<int> container_regs;
  std::vector<int> invalidate_regs;
};

struct regs_view {
  void* ctx = nullptr;
  size_t (*reg_size_fn)(void* ctx, int regno) = nullptr;
  target_status (*read_reg_fn)(void* ctx, int regno, std::span<std::byte> out) = nullptr;
  target_status (*write_reg_fn)(void* ctx, int regno, std::span<const std::byte> data) = nullptr;

  size_t reg_size(int regno) const { return reg_size_fn(ctx, regno); }
  target_status read_reg(int regno, std::span<std::byte> out) const { return read_reg_fn(ctx, regno, out); }
  target_status write_reg(int regno, std::span<const std::byte> data) const {
    return write_reg_fn(ctx, regno, data);
  }
};

struct mem_view {
  void* ctx = nullptr;
  target_status (*read_mem_fn)(void* ctx, uint64_t addr, std::span<std::byte> out) = nullptr;
  target_status (*write_mem_fn)(void* ctx, uint64_t addr, std::span<const std::byte> data) = nullptr;

  target_status read_mem(uint64_t addr, std::span<std::byte> out) const { return read_mem_fn(ctx, addr, out); }
  target_status write_mem(uint64_t addr, std::span<const std::byte> data) const {
    return write_mem_fn(ctx, addr, data);
  }
};

struct run_view {
  void* ctx = nullptr;
  resume_result (*resume_fn)(void* ctx, const resume_request& request) = nullptr;
  void (*interrupt_fn)(void* ctx) = nullptr;
  std::optional<stop_reason> (*poll_stop_fn)(void* ctx) = nullptr;
  void (*set_stop_notifier_fn)(void* ctx, stop_notifier notifier) = nullptr;

  resume_result resume(const resume_request& request) const { return resume_fn(ctx, request); }

  void interrupt() const {
    if (interrupt_fn) {
      interrupt_fn(ctx);
    }
  }

  std::optional<stop_reason> poll_stop() const {
    if (poll_stop_fn) {
      return poll_stop_fn(ctx);
    }
    return std::nullopt;
  }

  void set_stop_notifier(stop_notifier notifier) const {
    if (set_stop_notifier_fn) {
      set_stop_notifier_fn(ctx, notifier);
    }
  }
};

struct breakpoints_view {
  void* ctx = nullptr;
  target_status (*set_breakpoint_fn)(void* ctx, const breakpoint_spec& request) = nullptr;
  target_status (*remove_breakpoint_fn)(void* ctx, const breakpoint_spec& request) = nullptr;

  target_status set_breakpoint(const breakpoint_spec& request) const { return set_breakpoint_fn(ctx, request); }
  target_status remove_breakpoint(const breakpoint_spec& request) const {
    return remove_breakpoint_fn(ctx, request);
  }
};

struct memory_map_view {
  void* ctx = nullptr;
  std::optional<memory_region> (*region_for_fn)(void* ctx, uint64_t addr) = nullptr;
  std::vector<memory_region> (*regions_fn)(void* ctx) = nullptr;

  std::optional<memory_region> region_for(uint64_t addr) const { return region_for_fn(ctx, addr); }
  std::vector<memory_region> regions() const { return regions_fn(ctx); }
};

struct threads_view {
  void* ctx = nullptr;
  std::vector<uint64_t> (*thread_ids_fn)(void* ctx) = nullptr;
  uint64_t (*current_thread_fn)(void* ctx) = nullptr;
  target_status (*set_current_thread_fn)(void* ctx, uint64_t tid) = nullptr;
  std::optional<uint64_t> (*thread_pc_fn)(void* ctx, uint64_t tid) = nullptr;
  std::optional<std::string> (*thread_name_fn)(void* ctx, uint64_t tid) = nullptr;
  std::optional<stop_reason> (*thread_stop_reason_fn)(void* ctx, uint64_t tid) = nullptr;

  std::vector<uint64_t> thread_ids() const { return thread_ids_fn(ctx); }
  uint64_t current_thread() const { return current_thread_fn(ctx); }
  target_status set_current_thread(uint64_t tid) const { return set_current_thread_fn(ctx, tid); }
  std::optional<uint64_t> thread_pc(uint64_t tid) const { return thread_pc_fn(ctx, tid); }
  std::optional<std::string> thread_name(uint64_t tid) const { return thread_name_fn(ctx, tid); }
  std::optional<stop_reason> thread_stop_reason(uint64_t tid) const { return thread_stop_reason_fn(ctx, tid); }
};

struct host_info_view {
  void* ctx = nullptr;
  std::optional<host_info> (*get_host_info_fn)(void* ctx) = nullptr;

  std::optional<host_info> get_host_info() const { return get_host_info_fn(ctx); }
};

struct process_info_view {
  void* ctx = nullptr;
  std::optional<process_info> (*get_process_info_fn)(void* ctx) = nullptr;

  std::optional<process_info> get_process_info() const { return get_process_info_fn(ctx); }
};

struct shlib_view {
  void* ctx = nullptr;
  std::optional<shlib_info> (*get_shlib_info_fn)(void* ctx) = nullptr;

  std::optional<shlib_info> get_shlib_info() const { return get_shlib_info_fn(ctx); }
};

struct register_info_view {
  void* ctx = nullptr;
  std::optional<register_info> (*get_register_info_fn)(void* ctx, int regno) = nullptr;

  std::optional<register_info> get_register_info(int regno) const { return get_register_info_fn(ctx, regno); }
};

struct target_view {
  regs_view regs;
  mem_view mem;
  run_view run;
  std::optional<breakpoints_view> breakpoints;
  std::optional<memory_map_view> memory_map;
  std::optional<threads_view> threads;
  std::optional<host_info_view> host;
  std::optional<process_info_view> process;
  std::optional<shlib_view> shlib;
  std::optional<register_info_view> reg_info;
};

class target {
public:
  explicit target(target_view view) : view_(std::move(view)) {}

  const target_view& view() const { return view_; }

private:
  target_view view_{};
};

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
concept breakpoints_capability = requires(T& t, const breakpoint_spec& request) {
  { t.set_breakpoint(request) } -> std::same_as<target_status>;
  { t.remove_breakpoint(request) } -> std::same_as<target_status>;
};

template <typename T>
concept memory_map_capability = requires(T& t, uint64_t addr) {
  { t.region_for(addr) } -> std::same_as<std::optional<memory_region>>;
  { t.regions() } -> std::same_as<std::vector<memory_region>>;
};

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
  return view;
}

template <typename T>
breakpoints_view make_breakpoints_view(T& breakpoints) {
  breakpoints_view view;
  view.ctx = std::addressof(breakpoints);
  view.set_breakpoint_fn = [](void* ctx, const breakpoint_spec& request) -> target_status {
    return static_cast<T*>(ctx)->set_breakpoint(request);
  };
  view.remove_breakpoint_fn = [](void* ctx, const breakpoint_spec& request) -> target_status {
    return static_cast<T*>(ctx)->remove_breakpoint(request);
  };
  return view;
}

template <typename T>
memory_map_view make_memory_map_view(T& memory_map) {
  memory_map_view view;
  view.ctx = std::addressof(memory_map);
  view.region_for_fn = [](void* ctx, uint64_t addr) -> std::optional<memory_region> {
    return static_cast<T*>(ctx)->region_for(addr);
  };
  view.regions_fn = [](void* ctx) -> std::vector<memory_region> { return static_cast<T*>(ctx)->regions(); };
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
  constexpr int matches = breakpoints_capability<T> + threads_capability<T> + memory_map_capability<T> +
                          host_info_capability<T> + process_info_capability<T> + shlib_capability<T> +
                          register_info_capability<T>;
  static_assert(matches == 1, "Optional capability object must implement exactly one optional capability.");

  if constexpr (breakpoints_capability<T>) {
    view.breakpoints = make_breakpoints_view(obj);
  } else if constexpr (threads_capability<T>) {
    view.threads = make_threads_view(obj);
  } else if constexpr (memory_map_capability<T>) {
    view.memory_map = make_memory_map_view(obj);
  } else if constexpr (host_info_capability<T>) {
    view.host = make_host_info_view(obj);
  } else if constexpr (process_info_capability<T>) {
    view.process = make_process_info_view(obj);
  } else if constexpr (shlib_capability<T>) {
    view.shlib = make_shlib_view(obj);
  } else if constexpr (register_info_capability<T>) {
    view.reg_info = make_register_info_view(obj);
  } else {
    static_assert(always_false<T>, "Optional capability object must implement exactly one optional capability.");
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
  constexpr int memory_map_count = (0 + ... + detail::memory_map_capability<Opts>);
  static_assert(memory_map_count <= 1, "Memory map capability provided multiple times.");
  constexpr int host_count = (0 + ... + detail::host_info_capability<Opts>);
  static_assert(host_count <= 1, "Host info capability provided multiple times.");
  constexpr int process_count = (0 + ... + detail::process_info_capability<Opts>);
  static_assert(process_count <= 1, "Process info capability provided multiple times.");
  constexpr int shlib_count = (0 + ... + detail::shlib_capability<Opts>);
  static_assert(shlib_count <= 1, "Shlib capability provided multiple times.");
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
