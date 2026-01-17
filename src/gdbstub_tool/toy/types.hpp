#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace gdbstub::toy {

enum class execution_mode {
  blocking,
  polling,
  async,
};

struct config {
  uint32_t reg_bits = 32;
  size_t reg_count = 8;
  int pc_reg_num = 0;
  uint64_t start_pc = 0x1000;
  uint64_t instruction_size = 4;
  size_t max_steps = 256;
  // Max snapshots retained for reverse execution.
  size_t history_limit = 1024;
  execution_mode mode = execution_mode::blocking;
  size_t memory_size = 0x4000;
  std::string triple = "toy-unknown-elf";
  std::string endian = "little";
  std::string osabi = "none";
  std::string hostname = "toy-target";
  int pid = 1;
  std::optional<uint64_t> shlib_info_addr;
  std::vector<uint64_t> thread_ids = {1};
  std::string xml_arch_name = "org.gnu.gdb.toy";
  std::string architecture = "toy";
};

} // namespace gdbstub::toy
