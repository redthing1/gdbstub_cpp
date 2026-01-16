#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "gdbstub/target.hpp"
#include "gdbstub_tool/toy/layout.hpp"
#include "gdbstub_tool/toy/machine.hpp"
#include "gdbstub_tool/toy/runner.hpp"
#include "gdbstub_tool/toy/threads.hpp"
#include "gdbstub_tool/toy/types.hpp"

namespace gdbstub::toy {

class target final : public register_access,
                     public memory_access,
                     public run_control,
                     public breakpoint_access,
                     public memory_map,
                     public host_info_provider,
                     public process_info_provider,
                     public shlib_info_provider,
                     public thread_access {
public:
  explicit target(config cfg)
      : config_(std::move(cfg)),
        layout_(config_),
        machine_(config_),
        threads_(config_.thread_ids),
        runner_(machine_, threads_, config_.mode, config_.max_steps) {}

  const layout& layout_spec() const { return layout_; }

  gdbstub::arch_spec make_arch_spec() const {
    arch_spec spec;
    spec.target_xml = layout_.target_xml();
    spec.xml_arch_name = layout_.xml_arch_name();
    spec.osabi = config_.osabi;
    spec.reg_count = layout_.reg_count();
    spec.pc_reg_num = layout_.pc_reg_num();
    return spec;
  }

  target_handles handles() {
    target_handles out{*this, *this, *this};
    out.breakpoints = this;
    out.memory = this;
    out.threads = this;
    out.host = this;
    out.process = this;
    out.shlib = this;
    return out;
  }

  void set_mode(execution_mode mode) {
    config_.mode = mode;
    runner_.set_mode(mode);
  }

  void set_async_callback(std::function<void(const stop_reason&)> callback) {
    runner_.set_async_callback(std::move(callback));
  }

  void set_reg(int regno, uint64_t value) { machine_.set_reg(regno, value); }
  uint64_t reg_value(int regno) const { return machine_.reg_value(regno); }

  size_t reg_size(int regno) const override { return layout_.reg_size(regno); }

  target_status read_reg(int regno, std::span<std::byte> out) override {
    return machine_.read_reg(regno, out);
  }

  target_status write_reg(int regno, std::span<const std::byte> data) override {
    return machine_.write_reg(regno, data);
  }

  target_status read_mem(uint64_t addr, std::span<std::byte> out) override {
    return machine_.read_mem(addr, out);
  }

  target_status write_mem(uint64_t addr, std::span<const std::byte> data) override {
    return machine_.write_mem(addr, data);
  }

  resume_result resume(const resume_request& request) override { return runner_.resume(request); }
  void interrupt() override { runner_.interrupt(); }
  std::optional<stop_reason> poll_stop() override { return runner_.poll_stop(); }

  target_status set_breakpoint(const breakpoint_access::spec& request) override {
    if (request.type != breakpoint_access::type::software && request.type != breakpoint_access::type::hardware) {
      return target_status::unsupported;
    }
    machine_.add_breakpoint(request.addr);
    return target_status::ok;
  }

  target_status remove_breakpoint(const breakpoint_access::spec& request) override {
    if (request.type != breakpoint_access::type::software && request.type != breakpoint_access::type::hardware) {
      return target_status::unsupported;
    }
    machine_.remove_breakpoint(request.addr);
    return target_status::ok;
  }

  std::optional<memory_region> region_for(uint64_t addr) override {
    if (addr >= machine_.memory_size()) {
      return std::nullopt;
    }
    return memory_region{0, static_cast<uint64_t>(machine_.memory_size()), "rwx"};
  }

  std::vector<memory_region> regions() override {
    return {memory_region{0, static_cast<uint64_t>(machine_.memory_size()), "rwx"}};
  }

  std::optional<host_info> get_host_info() override {
    host_info info;
    info.triple = config_.triple;
    info.endian = config_.endian;
    info.ptr_size = static_cast<int>(config_.reg_bits / 8);
    info.hostname = config_.hostname;
    return info;
  }

  std::optional<process_info> get_process_info() override {
    process_info info;
    info.pid = config_.pid;
    info.triple = config_.triple;
    info.endian = config_.endian;
    info.ptr_size = static_cast<int>(config_.reg_bits / 8);
    info.ostype = config_.osabi;
    return info;
  }

  std::optional<shlib_info> get_shlib_info() override {
    if (!config_.shlib_info_addr) {
      return std::nullopt;
    }
    shlib_info info;
    info.info_addr = config_.shlib_info_addr;
    return info;
  }

  std::vector<uint64_t> thread_ids() override { return threads_.ids(); }
  uint64_t current_thread() const override { return threads_.current_thread(); }

  target_status set_current_thread(uint64_t tid) override { return threads_.set_current_thread(tid); }

  std::optional<uint64_t> thread_pc(uint64_t tid) override {
    if (tid == threads_.current_thread()) {
      return machine_.pc();
    }
    return std::nullopt;
  }

  std::optional<std::string> thread_name(uint64_t tid) override {
    if (tid == threads_.current_thread()) {
      return std::string("toy-thread");
    }
    return std::nullopt;
  }

  std::optional<stop_reason> thread_stop_reason(uint64_t tid) override {
    if (tid == threads_.current_thread()) {
      return runner_.last_stop();
    }
    return std::nullopt;
  }

private:
  config config_;
  layout layout_;
  machine machine_;
  threads threads_;
  runner runner_;
};

} // namespace gdbstub::toy
