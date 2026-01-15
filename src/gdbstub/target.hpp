#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "gdbstub/rsp_types.hpp"

namespace gdbstub {

class register_access {
public:
  virtual ~register_access() = default;
  virtual size_t reg_size(int regno) const = 0;
  virtual target_status read_reg(int regno, std::span<std::byte> out) = 0;
  virtual target_status write_reg(int regno, std::span<const std::byte> data) = 0;
};

class memory_access {
public:
  virtual ~memory_access() = default;
  virtual target_status read_mem(uint64_t addr, std::span<std::byte> out) = 0;
  virtual target_status write_mem(uint64_t addr, std::span<const std::byte> data) = 0;
};

class run_control {
public:
  virtual ~run_control() = default;
  virtual resume_result resume(const resume_request& request) = 0;
  virtual void interrupt() {}
  virtual std::optional<stop_reason> poll_stop() { return std::nullopt; }
};

class breakpoint_access {
public:
  virtual ~breakpoint_access() = default;
  enum class type {
    software = 0,
    hardware = 1,
    watch_write = 2,
    watch_read = 3,
    watch_access = 4,
  };

  struct spec {
    type type = type::software;
    uint64_t addr = 0;
    uint32_t length = 0;
  };

  virtual target_status set_breakpoint(const spec& request) = 0;
  virtual target_status remove_breakpoint(const spec& request) = 0;
};

struct memory_region {
  uint64_t start = 0;
  uint64_t size = 0;
  std::string permissions;
};

class memory_map {
public:
  virtual ~memory_map() = default;
  virtual std::optional<memory_region> region_for(uint64_t addr) = 0;
  virtual std::vector<memory_region> regions() { return {}; }
};

class thread_access {
public:
  virtual ~thread_access() = default;
  virtual std::vector<uint64_t> thread_ids() = 0;
  virtual uint64_t current_thread() const = 0;
  virtual target_status set_current_thread(uint64_t tid) = 0;
  virtual std::optional<uint64_t> thread_pc(uint64_t tid) = 0;
  virtual std::optional<std::string> thread_name(uint64_t tid) = 0;
  virtual std::optional<stop_reason> thread_stop_reason(uint64_t tid) { return std::nullopt; }
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

class host_info_provider {
public:
  virtual ~host_info_provider() = default;
  virtual std::optional<host_info> get_host_info() = 0;
};

class process_info_provider {
public:
  virtual ~process_info_provider() = default;
  virtual std::optional<process_info> get_process_info() = 0;
};

struct shlib_info {
  std::optional<uint64_t> info_addr;
};

class shlib_info_provider {
public:
  virtual ~shlib_info_provider() = default;
  virtual std::optional<shlib_info> get_shlib_info() = 0;
};

struct target_handles {
  register_access& regs;
  memory_access& mem;
  run_control& run;
  breakpoint_access* breakpoints = nullptr;
  memory_map* memory = nullptr;
  thread_access* threads = nullptr;
  host_info_provider* host = nullptr;
  process_info_provider* process = nullptr;
  shlib_info_provider* shlib = nullptr;
};

} // namespace gdbstub
