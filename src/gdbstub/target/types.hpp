#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "gdbstub/protocol/rsp_types.hpp"

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

  static breakpoint_spec software(uint64_t addr_value, uint32_t length_value = 0) {
    return {breakpoint_type::software, addr_value, length_value};
  }

  static breakpoint_spec hardware(uint64_t addr_value, uint32_t length_value = 0) {
    return {breakpoint_type::hardware, addr_value, length_value};
  }

  static breakpoint_spec watch_write(uint64_t addr_value, uint32_t length_value) {
    return {breakpoint_type::watch_write, addr_value, length_value};
  }

  static breakpoint_spec watch_read(uint64_t addr_value, uint32_t length_value) {
    return {breakpoint_type::watch_read, addr_value, length_value};
  }

  static breakpoint_spec watch_access(uint64_t addr_value, uint32_t length_value) {
    return {breakpoint_type::watch_access, addr_value, length_value};
  }
};

struct bytecode_expr {
  std::vector<std::byte> bytes;
};

struct breakpoint_commands {
  bool persist = false;
  std::vector<bytecode_expr> commands;
};

struct breakpoint_request {
  breakpoint_spec spec;
  std::optional<uint64_t> thread_id;
  std::vector<bytecode_expr> conditions;
  std::optional<breakpoint_commands> commands;
};

struct run_capabilities {
  bool reverse_continue = false;
  bool reverse_step = false;
  bool range_step = false;
  bool non_stop = false;
};

struct breakpoint_capabilities {
  bool software = false;
  bool hardware = false;
  bool watch_read = false;
  bool watch_write = false;
  bool watch_access = false;
  bool supports_thread_suffix = false;
  bool supports_conditional = false;
  bool supports_commands = false;
};

enum class mem_perm : uint8_t {
  none = 0,
  read = 1 << 0,
  write = 1 << 1,
  exec = 1 << 2,
};

constexpr mem_perm operator|(mem_perm lhs, mem_perm rhs) {
  return static_cast<mem_perm>(static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs));
}

constexpr mem_perm operator&(mem_perm lhs, mem_perm rhs) {
  return static_cast<mem_perm>(static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs));
}

constexpr mem_perm& operator|=(mem_perm& lhs, mem_perm rhs) {
  lhs = lhs | rhs;
  return lhs;
}

constexpr bool has_perm(mem_perm value, mem_perm flag) {
  return (value & flag) != mem_perm::none;
}

struct memory_region {
  uint64_t start = 0;
  uint64_t size = 0;
  mem_perm perms = mem_perm::none;
  std::optional<std::string> name;
  std::vector<std::string> types;
};

struct memory_region_info {
  uint64_t start = 0;
  uint64_t size = 0;
  bool mapped = false;
  mem_perm perms = mem_perm::none;
  std::optional<std::string> name;
  std::vector<std::string> types;
};

inline uint64_t region_end(const memory_region& region) {
  if (region.size == 0) {
    return region.start;
  }
  if (region.start > std::numeric_limits<uint64_t>::max() - region.size) {
    return std::numeric_limits<uint64_t>::max();
  }
  return region.start + region.size;
}

inline memory_region_info mapped_region_info(const memory_region& region) {
  memory_region_info info;
  info.start = region.start;
  info.size = region.size;
  info.mapped = true;
  info.perms = region.perms;
  info.name = region.name;
  info.types = region.types;
  return info;
}

inline memory_region_info unmapped_region_info(uint64_t start, uint64_t size) {
  memory_region_info info;
  info.start = start;
  info.size = size;
  info.mapped = false;
  return info;
}

inline std::optional<memory_region_info> region_info_from_map(
    std::span<const memory_region> regions,
    uint64_t addr
) {
  for (const auto& region : regions) {
    auto end = region_end(region);
    if (addr >= region.start && addr < end) {
      return mapped_region_info(region);
    }
  }
  return std::nullopt;
}

struct host_info {
  std::string triple;
  std::string endian;
  int ptr_size = 0;
  std::string hostname;
  std::optional<std::string> os_version;
  std::optional<std::string> os_build;
  std::optional<std::string> os_kernel;
  std::optional<int> addressing_bits;
  std::optional<int> low_mem_addressing_bits;
  std::optional<int> high_mem_addressing_bits;
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

enum class library_address_kind : uint8_t {
  segment = 0,
  section = 1,
};

struct library_entry {
  std::string name;
  library_address_kind kind = library_address_kind::segment;
  std::vector<uint64_t> addresses;

  static library_entry segment(std::string name_value, std::vector<uint64_t> addresses_value) {
    library_entry entry;
    entry.name = std::move(name_value);
    entry.kind = library_address_kind::segment;
    entry.addresses = std::move(addresses_value);
    return entry;
  }

  static library_entry section(std::string name_value, std::vector<uint64_t> addresses_value) {
    library_entry entry;
    entry.name = std::move(name_value);
    entry.kind = library_address_kind::section;
    entry.addresses = std::move(addresses_value);
    return entry;
  }
};

struct process_launch_request {
  std::optional<std::string> filename;
  std::vector<std::string> args;
};

enum class offsets_kind {
  section,
  segment,
};

struct offsets_info {
  offsets_kind kind = offsets_kind::section;
  uint64_t text = 0;
  std::optional<uint64_t> data;
  std::optional<uint64_t> bss;

  static offsets_info section(
      uint64_t text_value,
      uint64_t data_value,
      std::optional<uint64_t> bss_value = std::nullopt
  ) {
    offsets_info info;
    info.kind = offsets_kind::section;
    info.text = text_value;
    info.data = data_value;
    info.bss = bss_value;
    return info;
  }

  static offsets_info segment(
      uint64_t text_value,
      std::optional<uint64_t> data_value = std::nullopt
  ) {
    offsets_info info;
    info.kind = offsets_kind::segment;
    info.text = text_value;
    info.data = data_value;
    info.bss.reset();
    return info;
  }
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

} // namespace gdbstub
