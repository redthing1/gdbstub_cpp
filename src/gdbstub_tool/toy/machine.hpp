#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_set>
#include <vector>

#include "gdbstub/rsp_types.hpp"
#include "gdbstub/target.hpp"
#include "gdbstub_tool/toy/types.hpp"

namespace gdbstub::toy {

class machine {
public:
  struct snapshot {
    std::vector<uint64_t> regs;
    std::vector<std::byte> memory;
  };

  explicit machine(const config& cfg)
      : reg_bits_(cfg.reg_bits),
        reg_count_(cfg.reg_count),
        pc_reg_num_(cfg.pc_reg_num),
        instruction_size_(cfg.instruction_size),
        memory_size_(cfg.memory_size) {
    regs_.assign(reg_count_, 0);
    memory_.assign(memory_size_, std::byte{0});
    if (valid_reg(cfg.pc_reg_num)) {
      regs_[static_cast<size_t>(cfg.pc_reg_num)] = mask_value(cfg.start_pc);
    }
  }

  size_t reg_count() const { return reg_count_; }
  int pc_reg_num() const { return pc_reg_num_; }
  uint32_t reg_bits() const { return reg_bits_; }
  size_t reg_size(int regno) const {
    if (!valid_reg(regno) || reg_bytes() == 0) {
      return 0;
    }
    return reg_bytes();
  }
  size_t memory_size() const { return memory_size_; }

  target_status read_reg(int regno, std::span<std::byte> out) const {
    if (!valid_reg(regno) || out.size() != reg_bytes()) {
      return target_status::invalid;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    write_reg_bytes(regs_[static_cast<size_t>(regno)], out);
    return target_status::ok;
  }

  target_status write_reg(int regno, std::span<const std::byte> data) {
    if (!valid_reg(regno) || data.size() != reg_bytes()) {
      return target_status::invalid;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    regs_[static_cast<size_t>(regno)] = mask_value(read_reg_bytes(data));
    return target_status::ok;
  }

  void set_reg(int regno, uint64_t value) {
    if (!valid_reg(regno)) {
      return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    regs_[static_cast<size_t>(regno)] = mask_value(value);
  }

  uint64_t reg_value(int regno) const {
    if (!valid_reg(regno)) {
      return 0;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return regs_[static_cast<size_t>(regno)];
  }

  target_status read_mem(uint64_t addr, std::span<std::byte> out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (addr + out.size() > memory_.size()) {
      return target_status::fault;
    }
    std::memcpy(out.data(), memory_.data() + addr, out.size());
    return target_status::ok;
  }

  target_status write_mem(uint64_t addr, std::span<const std::byte> data) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (addr + data.size() > memory_.size()) {
      return target_status::fault;
    }
    std::memcpy(memory_.data() + addr, data.data(), data.size());
    return target_status::ok;
  }

  void add_breakpoint(const gdbstub::breakpoint_spec& spec) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (spec.type == gdbstub::breakpoint_type::software) {
      sw_breakpoints_.insert(spec.addr);
      return;
    }
    if (spec.type == gdbstub::breakpoint_type::hardware) {
      hw_breakpoints_.insert(spec.addr);
      return;
    }
    watchpoints_.push_back({spec.type, spec.addr, spec.length});
  }

  void remove_breakpoint(const gdbstub::breakpoint_spec& spec) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (spec.type == gdbstub::breakpoint_type::software) {
      sw_breakpoints_.erase(spec.addr);
      return;
    }
    if (spec.type == gdbstub::breakpoint_type::hardware) {
      hw_breakpoints_.erase(spec.addr);
      return;
    }
    auto it = std::remove_if(watchpoints_.begin(), watchpoints_.end(), [&](const watchpoint& wp) {
      return wp.type == spec.type && wp.addr == spec.addr && wp.length == spec.length;
    });
    watchpoints_.erase(it, watchpoints_.end());
  }

  snapshot capture_snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot shot;
    shot.regs = regs_;
    shot.memory = memory_;
    return shot;
  }

  void restore_snapshot(const snapshot& shot) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (shot.regs.size() == regs_.size()) {
      regs_ = shot.regs;
    }
    if (shot.memory.size() == memory_.size()) {
      memory_ = shot.memory;
    }
  }

  uint64_t pc() const {
    if (!valid_reg(pc_reg_num_)) {
      return 0;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return regs_[static_cast<size_t>(pc_reg_num_)];
  }

  void set_pc(uint64_t addr) {
    if (!valid_reg(pc_reg_num_)) {
      return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    regs_[static_cast<size_t>(pc_reg_num_)] = mask_value(addr);
  }

  void advance_pc() {
    if (!valid_reg(pc_reg_num_)) {
      return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto index = static_cast<size_t>(pc_reg_num_);
    regs_[index] = mask_value(regs_[index] + instruction_size_);
  }

  std::optional<stop_reason> stop_if_breakpoint(uint64_t thread_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stop_if_breakpoint_locked(thread_id);
  }

  std::optional<stop_reason> stop_if_watchpoint(uint64_t thread_id, uint64_t read_addr, uint64_t write_addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stop_if_watchpoint_locked(thread_id, read_addr, write_addr);
  }

  std::optional<stop_reason> step_and_check(uint64_t thread_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (auto stop = stop_if_breakpoint_locked(thread_id)) {
      return stop;
    }
    uint64_t access_addr = 0;
    if (valid_reg(pc_reg_num_)) {
      auto index = static_cast<size_t>(pc_reg_num_);
      regs_[index] = mask_value(regs_[index] + instruction_size_);
      if (!memory_.empty()) {
        access_addr = regs_[index] % memory_.size();
      }
    }
    uint64_t write_addr = memory_.empty() ? 0 : (access_addr + 1) % std::max<size_t>(1, memory_.size());
    if (auto stop = stop_if_watchpoint_locked(thread_id, access_addr, write_addr)) {
      return stop;
    }
    return stop_if_breakpoint_locked(thread_id);
  }

  stop_reason signal_stop(uint64_t thread_id) const {
    stop_reason reason;
    reason.kind = stop_kind::signal;
    reason.signal = 5;
    reason.thread_id = thread_id;
    return reason;
  }

private:
  struct watchpoint {
    gdbstub::breakpoint_type type = gdbstub::breakpoint_type::watch_access;
    uint64_t addr = 0;
    uint32_t length = 0;
  };

  bool valid_reg(int regno) const {
    return regno >= 0 && static_cast<size_t>(regno) < reg_count_;
  }

  size_t reg_bytes() const {
    if (reg_bits_ == 0 || (reg_bits_ % 8) != 0) {
      return 0;
    }
    return reg_bits_ / 8;
  }

  uint64_t mask_value(uint64_t value) const {
    if (reg_bits_ >= 64) {
      return value;
    }
    if (reg_bits_ == 0) {
      return 0;
    }
    uint64_t mask = (1ULL << reg_bits_) - 1ULL;
    return value & mask;
  }

  static void write_reg_bytes(uint64_t value, std::span<std::byte> out) {
    for (size_t i = 0; i < out.size(); ++i) {
      out[i] = std::byte(static_cast<uint8_t>((value >> (i * 8)) & 0xff));
    }
  }

  static uint64_t read_reg_bytes(std::span<const std::byte> data) {
    uint64_t value = 0;
    for (size_t i = 0; i < data.size(); ++i) {
      value |= static_cast<uint64_t>(static_cast<uint8_t>(data[i])) << (i * 8);
    }
    return value;
  }

  std::optional<stop_reason> stop_if_breakpoint_locked(uint64_t thread_id) const {
    if (!valid_reg(pc_reg_num_)) {
      return std::nullopt;
    }
    auto pc_value = regs_[static_cast<size_t>(pc_reg_num_)];
    if (hw_breakpoints_.find(pc_value) != hw_breakpoints_.end()) {
      stop_reason reason;
      reason.kind = stop_kind::hw_break;
      reason.signal = 5;
      reason.addr = pc_value;
      reason.thread_id = thread_id;
      return reason;
    }
    if (sw_breakpoints_.find(pc_value) != sw_breakpoints_.end()) {
      stop_reason reason;
      reason.kind = stop_kind::sw_break;
      reason.signal = 5;
      reason.addr = pc_value;
      reason.thread_id = thread_id;
      return reason;
    }
    return std::nullopt;
  }

  std::optional<stop_reason> stop_if_watchpoint_locked(
      uint64_t thread_id,
      uint64_t read_addr,
      uint64_t write_addr
  ) const {
    auto matches = [](uint64_t access, uint64_t addr, uint32_t length) {
      uint64_t size = length > 0 ? static_cast<uint64_t>(length) : 1;
      return access >= addr && access < addr + size;
    };

    for (const auto& wp : watchpoints_) {
      if (wp.type == gdbstub::breakpoint_type::watch_access) {
        if (matches(read_addr, wp.addr, wp.length) || matches(write_addr, wp.addr, wp.length)) {
          stop_reason reason;
          reason.kind = stop_kind::watch_access;
          reason.signal = 5;
          reason.addr = matches(read_addr, wp.addr, wp.length) ? read_addr : write_addr;
          reason.thread_id = thread_id;
          return reason;
        }
      }
    }
    for (const auto& wp : watchpoints_) {
      if (wp.type == gdbstub::breakpoint_type::watch_write && matches(write_addr, wp.addr, wp.length)) {
        stop_reason reason;
        reason.kind = stop_kind::watch_write;
        reason.signal = 5;
        reason.addr = write_addr;
        reason.thread_id = thread_id;
        return reason;
      }
    }
    for (const auto& wp : watchpoints_) {
      if (wp.type == gdbstub::breakpoint_type::watch_read && matches(read_addr, wp.addr, wp.length)) {
        stop_reason reason;
        reason.kind = stop_kind::watch_read;
        reason.signal = 5;
        reason.addr = read_addr;
        reason.thread_id = thread_id;
        return reason;
      }
    }
    return std::nullopt;
  }

  uint32_t reg_bits_ = 0;
  size_t reg_count_ = 0;
  int pc_reg_num_ = -1;
  uint64_t instruction_size_ = 0;
  size_t memory_size_ = 0;

  mutable std::mutex mutex_;
  std::vector<uint64_t> regs_;
  std::vector<std::byte> memory_;
  std::unordered_set<uint64_t> sw_breakpoints_;
  std::unordered_set<uint64_t> hw_breakpoints_;
  std::vector<watchpoint> watchpoints_;
};

} // namespace gdbstub::toy
