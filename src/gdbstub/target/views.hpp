#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "gdbstub/lldb/types.hpp"
#include "gdbstub/target/types.hpp"

namespace gdbstub {

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
  std::optional<run_capabilities> (*get_run_capabilities_fn)(void* ctx) = nullptr;

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

  std::optional<run_capabilities> capabilities() const {
    if (get_run_capabilities_fn) {
      return get_run_capabilities_fn(ctx);
    }
    return std::nullopt;
  }
};

struct breakpoints_view {
  void* ctx = nullptr;
  target_status (*set_breakpoint_fn)(void* ctx, const breakpoint_request& request) = nullptr;
  target_status (*remove_breakpoint_fn)(void* ctx, const breakpoint_request& request) = nullptr;
  std::optional<breakpoint_capabilities> (*get_breakpoint_capabilities_fn)(void* ctx) = nullptr;

  target_status set_breakpoint(const breakpoint_request& request) const {
    return set_breakpoint_fn(ctx, request);
  }
  target_status remove_breakpoint(const breakpoint_request& request) const {
    return remove_breakpoint_fn(ctx, request);
  }

  std::optional<breakpoint_capabilities> capabilities() const {
    if (get_breakpoint_capabilities_fn) {
      return get_breakpoint_capabilities_fn(ctx);
    }
    return std::nullopt;
  }
};

struct memory_layout_view {
  void* ctx = nullptr;
  std::optional<memory_region_info> (*region_info_fn)(void* ctx, uint64_t addr) = nullptr;
  std::vector<memory_region> (*memory_map_fn)(void* ctx) = nullptr;

  bool has_region_info() const { return region_info_fn != nullptr; }
  bool has_memory_map() const { return memory_map_fn != nullptr; }

  std::optional<memory_region_info> region_info(uint64_t addr) const {
    if (!region_info_fn) {
      return std::nullopt;
    }
    return region_info_fn(ctx, addr);
  }

  std::vector<memory_region> memory_map() const {
    if (!memory_map_fn) {
      return {};
    }
    return memory_map_fn(ctx);
  }
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

struct libraries_view {
  void* ctx = nullptr;
  std::vector<library_entry> (*get_libraries_fn)(void* ctx) = nullptr;
  std::optional<uint64_t> (*generation_fn)(void* ctx) = nullptr;

  std::vector<library_entry> libraries() const {
    if (!get_libraries_fn) {
      return {};
    }
    return get_libraries_fn(ctx);
  }

  std::optional<uint64_t> generation() const {
    if (!generation_fn) {
      return std::nullopt;
    }
    return generation_fn(ctx);
  }
};

struct process_control_view {
  void* ctx = nullptr;
  std::optional<resume_result> (*launch_fn)(void* ctx, const process_launch_request& request) = nullptr;
  std::optional<resume_result> (*attach_fn)(void* ctx, uint64_t pid) = nullptr;
  target_status (*kill_fn)(void* ctx, std::optional<uint64_t> pid) = nullptr;
  std::optional<resume_result> (*restart_fn)(void* ctx) = nullptr;

  std::optional<resume_result> launch(const process_launch_request& request) const {
    if (!launch_fn) {
      return std::nullopt;
    }
    return launch_fn(ctx, request);
  }

  std::optional<resume_result> attach(uint64_t pid) const {
    if (!attach_fn) {
      return std::nullopt;
    }
    return attach_fn(ctx, pid);
  }

  target_status kill(std::optional<uint64_t> pid) const {
    if (!kill_fn) {
      return target_status::unsupported;
    }
    return kill_fn(ctx, pid);
  }

  std::optional<resume_result> restart() const {
    if (!restart_fn) {
      return std::nullopt;
    }
    return restart_fn(ctx);
  }
};

struct offsets_view {
  void* ctx = nullptr;
  std::optional<offsets_info> (*get_offsets_info_fn)(void* ctx) = nullptr;

  std::optional<offsets_info> get_offsets_info() const { return get_offsets_info_fn(ctx); }
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
  std::optional<memory_layout_view> memory_layout;
  std::optional<threads_view> threads;
  std::optional<host_info_view> host;
  std::optional<process_info_view> process;
  std::optional<shlib_view> shlib;
  std::optional<libraries_view> libraries;
  std::optional<lldb::view> lldb;
  std::optional<process_control_view> process_control;
  std::optional<offsets_view> offsets;
  std::optional<register_info_view> reg_info;
};

class target {
public:
  explicit target(target_view view) : view_(std::move(view)) {}

  const target_view& view() const { return view_; }

private:
  target_view view_{};
};

} // namespace gdbstub
