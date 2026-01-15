#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gdbstub/target.hpp"

namespace gdbstub::toy {

enum class execution_mode {
  blocking,
  polling,
  async,
};

template <typename RegT>
class emulator final : public register_access,
                       public memory_access,
                       public run_control,
                       public breakpoint_access,
                       public memory_map,
                       public host_info_provider,
                       public process_info_provider,
                       public shlib_info_provider,
                       public thread_access {
public:
  struct options {
    size_t reg_count = 8;
    int pc_reg_num = 0;
    uint64_t start_pc = 0x1000;
    uint64_t instruction_size = 4;
    size_t max_steps = 256;
    execution_mode mode = execution_mode::blocking;
    size_t memory_size = 0x4000;
    std::string triple = "toy-unknown-elf";
    std::string endian = "little";
    std::string osabi = "none";
    std::optional<uint64_t> shlib_info_addr;
  };

  explicit emulator(options opts) : options_(std::move(opts)) {
    regs_.resize(options_.reg_count);
    memory_.resize(options_.memory_size);
    threads_.push_back(1);
    if (options_.pc_reg_num >= 0 && static_cast<size_t>(options_.pc_reg_num) < regs_.size()) {
      regs_[static_cast<size_t>(options_.pc_reg_num)] = static_cast<RegT>(options_.start_pc);
    }
  }

  ~emulator() override { stop_async(); }

  emulator(const emulator&) = delete;
  emulator& operator=(const emulator&) = delete;

  execution_mode mode() const { return options_.mode; }
  void set_mode(execution_mode mode) { options_.mode = mode; }

  void set_async_callback(std::function<void(const stop_reason&)> callback) { async_callback_ = std::move(callback); }

  size_t reg_count() const { return regs_.size(); }
  int pc_reg_num() const { return options_.pc_reg_num; }

  void set_reg(int regno, RegT value) {
    if (regno < 0 || static_cast<size_t>(regno) >= regs_.size()) {
      return;
    }
    regs_[static_cast<size_t>(regno)] = value;
  }

  RegT reg_value(int regno) const {
    if (regno < 0 || static_cast<size_t>(regno) >= regs_.size()) {
      return 0;
    }
    return regs_[static_cast<size_t>(regno)];
  }

  uint64_t pc() const { return static_cast<uint64_t>(reg_value(options_.pc_reg_num)); }
  void set_pc(uint64_t addr) { set_reg(options_.pc_reg_num, static_cast<RegT>(addr)); }

  std::vector<std::byte>& memory() { return memory_; }
  const std::vector<std::byte>& memory() const { return memory_; }

  size_t reg_size(int regno) const override {
    if (regno < 0 || static_cast<size_t>(regno) >= regs_.size()) {
      return 0;
    }
    return sizeof(RegT);
  }

  target_status read_reg(int regno, std::span<std::byte> out) override {
    if (regno < 0 || static_cast<size_t>(regno) >= regs_.size()) {
      return target_status::invalid;
    }
    if (out.size() != sizeof(RegT)) {
      return target_status::invalid;
    }
    auto value = regs_[static_cast<size_t>(regno)];
    for (size_t i = 0; i < sizeof(RegT); ++i) {
      out[i] = std::byte(static_cast<uint8_t>((static_cast<uint64_t>(value) >> (i * 8)) & 0xff));
    }
    return target_status::ok;
  }

  target_status write_reg(int regno, std::span<const std::byte> data) override {
    if (regno < 0 || static_cast<size_t>(regno) >= regs_.size()) {
      return target_status::invalid;
    }
    if (data.size() != sizeof(RegT)) {
      return target_status::invalid;
    }
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(RegT); ++i) {
      value |= static_cast<uint64_t>(static_cast<uint8_t>(data[i])) << (i * 8);
    }
    regs_[static_cast<size_t>(regno)] = static_cast<RegT>(value);
    return target_status::ok;
  }

  target_status read_mem(uint64_t addr, std::span<std::byte> out) override {
    if (addr + out.size() > memory_.size()) {
      return target_status::fault;
    }
    std::memcpy(out.data(), memory_.data() + addr, out.size());
    return target_status::ok;
  }

  target_status write_mem(uint64_t addr, std::span<const std::byte> data) override {
    if (addr + data.size() > memory_.size()) {
      return target_status::fault;
    }
    std::memcpy(memory_.data() + addr, data.data(), data.size());
    return target_status::ok;
  }

  resume_result resume(const resume_request& request) override {
    if (request.addr) {
      set_pc(*request.addr);
    }

    if (request.action == resume_action::step) {
      advance_pc();
      resume_result result;
      result.state = resume_result::state::stopped;
      result.stop = make_signal_stop();
      set_last_stop(result.stop);
      return result;
    }

    if (auto immediate = check_breakpoint()) {
      resume_result result;
      result.state = resume_result::state::stopped;
      result.stop = *immediate;
      set_last_stop(result.stop);
      return result;
    }

    resume_result result;
    switch (options_.mode) {
    case execution_mode::blocking:
      result.state = resume_result::state::stopped;
      result.stop = run_blocking();
      set_last_stop(result.stop);
      return result;
    case execution_mode::polling:
      running_.store(true);
      result.state = resume_result::state::running;
      return result;
    case execution_mode::async:
      start_async();
      result.state = resume_result::state::running;
      return result;
    }

    result.state = resume_result::state::stopped;
    result.stop = make_signal_stop();
    set_last_stop(result.stop);
    return result;
  }

  void interrupt() override {
    stop_requested_.store(true);
    running_.store(false);
    queue_stop(make_signal_stop());
  }

  std::optional<stop_reason> poll_stop() override {
    if (auto pending = take_pending_stop()) {
      return pending;
    }

    if (options_.mode != execution_mode::polling || !running_.load()) {
      return std::nullopt;
    }

    if (auto stop = step_and_check()) {
      running_.store(false);
      set_last_stop(*stop);
      return stop;
    }

    return std::nullopt;
  }

  target_status set_breakpoint(const breakpoint_access::spec& request) override {
    if (request.type != breakpoint_access::type::software && request.type != breakpoint_access::type::hardware) {
      return target_status::unsupported;
    }
    breakpoints_.insert(request.addr);
    return target_status::ok;
  }

  target_status remove_breakpoint(const breakpoint_access::spec& request) override {
    if (request.type != breakpoint_access::type::software && request.type != breakpoint_access::type::hardware) {
      return target_status::unsupported;
    }
    breakpoints_.erase(request.addr);
    return target_status::ok;
  }

  std::optional<memory_region> region_for(uint64_t addr) override {
    if (addr >= memory_.size()) {
      return std::nullopt;
    }
    return memory_region{0, static_cast<uint64_t>(memory_.size()), "rwx"};
  }

  std::vector<memory_region> regions() override {
    return {memory_region{0, static_cast<uint64_t>(memory_.size()), "rwx"}};
  }

  std::optional<host_info> get_host_info() override {
    host_info info;
    info.triple = options_.triple;
    info.endian = options_.endian;
    info.ptr_size = static_cast<int>(sizeof(RegT));
    info.hostname = "toy-target";
    return info;
  }

  std::optional<process_info> get_process_info() override {
    process_info info;
    info.pid = 1;
    info.triple = options_.triple;
    info.endian = options_.endian;
    info.ptr_size = static_cast<int>(sizeof(RegT));
    info.ostype = options_.osabi;
    return info;
  }

  std::optional<shlib_info> get_shlib_info() override {
    if (!options_.shlib_info_addr) {
      return std::nullopt;
    }
    shlib_info info;
    info.info_addr = options_.shlib_info_addr;
    return info;
  }

  std::vector<uint64_t> thread_ids() override { return threads_; }

  uint64_t current_thread() const override { return current_thread_; }

  target_status set_current_thread(uint64_t tid) override {
    for (auto id : threads_) {
      if (id == tid) {
        current_thread_ = tid;
        return target_status::ok;
      }
    }
    return target_status::invalid;
  }

  std::optional<uint64_t> thread_pc(uint64_t tid) override {
    if (tid == current_thread_) {
      return pc();
    }
    return std::nullopt;
  }

  std::optional<std::string> thread_name(uint64_t tid) override {
    if (tid == current_thread_) {
      return std::string("toy-thread");
    }
    return std::nullopt;
  }

  std::optional<stop_reason> thread_stop_reason(uint64_t tid) override {
    if (tid == current_thread_) {
      return get_last_stop();
    }
    return std::nullopt;
  }

private:
  void advance_pc() { set_pc(pc() + options_.instruction_size); }

  std::optional<stop_reason> check_breakpoint() {
    if (breakpoints_.find(pc()) == breakpoints_.end()) {
      return std::nullopt;
    }
    stop_reason reason;
    reason.kind = stop_kind::sw_break;
    reason.signal = 5;
    reason.addr = pc();
    reason.thread_id = current_thread_;
    return reason;
  }

  stop_reason make_signal_stop() const {
    stop_reason reason;
    reason.kind = stop_kind::signal;
    reason.signal = 5;
    reason.thread_id = current_thread_;
    return reason;
  }

  std::optional<stop_reason> step_and_check() {
    if (auto stop = check_breakpoint()) {
      return stop;
    }
    advance_pc();
    return check_breakpoint();
  }

  stop_reason run_blocking() {
    for (size_t i = 0; i < options_.max_steps; ++i) {
      if (auto stop = step_and_check()) {
        return *stop;
      }
    }
    return make_signal_stop();
  }

  void queue_stop(const stop_reason& reason) {
    bool notify = false;
    {
      std::lock_guard<std::mutex> lock(stop_mutex_);
      last_stop_ = reason;
      if (!pending_stop_) {
        pending_stop_ = reason;
        notify = true;
      }
    }
    if (notify && async_callback_) {
      async_callback_(reason);
    }
  }

  std::optional<stop_reason> take_pending_stop() {
    std::lock_guard<std::mutex> lock(stop_mutex_);
    if (!pending_stop_) {
      return std::nullopt;
    }
    auto stop = pending_stop_;
    pending_stop_.reset();
    return stop;
  }

  void set_last_stop(const stop_reason& reason) {
    std::lock_guard<std::mutex> lock(stop_mutex_);
    last_stop_ = reason;
  }

  std::optional<stop_reason> get_last_stop() {
    std::lock_guard<std::mutex> lock(stop_mutex_);
    return last_stop_;
  }

  void start_async() {
    stop_async();
    stop_requested_.store(false);
    running_.store(true);
    worker_ = std::thread([this]() {
      for (size_t i = 0; i < options_.max_steps; ++i) {
        if (stop_requested_.load()) {
          queue_stop(make_signal_stop());
          running_.store(false);
          return;
        }
        if (auto stop = step_and_check()) {
          queue_stop(*stop);
          running_.store(false);
          return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      queue_stop(make_signal_stop());
      running_.store(false);
    });
  }

  void stop_async() {
    stop_requested_.store(true);
    if (worker_.joinable()) {
      worker_.join();
    }
    running_.store(false);
  }

  options options_;
  std::vector<RegT> regs_;
  std::vector<std::byte> memory_;
  std::unordered_set<uint64_t> breakpoints_;
  std::vector<uint64_t> threads_;
  uint64_t current_thread_ = 1;

  std::atomic<bool> running_{false};
  std::atomic<bool> stop_requested_{false};
  std::mutex stop_mutex_;
  std::optional<stop_reason> pending_stop_;
  std::optional<stop_reason> last_stop_;
  std::thread worker_;
  std::function<void(const stop_reason&)> async_callback_;
};

} // namespace gdbstub::toy
