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

namespace detail {

class regs_component {
public:
  regs_component(layout& layout, machine& machine) : layout_(layout), machine_(machine) {}

  size_t reg_size(int regno) const { return layout_.reg_size(regno); }

  target_status read_reg(int regno, std::span<std::byte> out) { return machine_.read_reg(regno, out); }

  target_status write_reg(int regno, std::span<const std::byte> data) { return machine_.write_reg(regno, data); }

private:
  layout& layout_;
  machine& machine_;
};

class mem_component {
public:
  explicit mem_component(machine& machine) : machine_(machine) {}

  target_status read_mem(uint64_t addr, std::span<std::byte> out) { return machine_.read_mem(addr, out); }

  target_status write_mem(uint64_t addr, std::span<const std::byte> data) { return machine_.write_mem(addr, data); }

private:
  machine& machine_;
};

class register_info_component {
public:
  explicit register_info_component(layout& layout) : layout_(layout) {}

  std::optional<gdbstub::register_info> get_register_info(int regno) {
    if (regno < 0 || static_cast<size_t>(regno) >= layout_.registers().size()) {
      return std::nullopt;
    }
    const auto& reg = layout_.registers()[static_cast<size_t>(regno)];
    gdbstub::register_info info;
    info.name = reg.name;
    info.bitsize = static_cast<int>(reg.bits);
    info.encoding = "uint";
    info.format = "hex";
    info.set = "general";
    if (reg.is_pc) {
      info.generic = "pc";
    }
    return info;
  }

private:
  layout& layout_;
};

class run_component {
public:
  explicit run_component(runner& runner) : runner_(runner) {}

  resume_result resume(const resume_request& request) { return runner_.resume(request); }

  void interrupt() { runner_.interrupt(); }

  std::optional<stop_reason> poll_stop() { return runner_.poll_stop(); }

  void set_stop_notifier(stop_notifier notifier) { runner_.set_stop_notifier(notifier); }

  run_capabilities capabilities() const { return runner_.capabilities(); }

private:
  runner& runner_;
};

class breakpoints_component {
public:
  explicit breakpoints_component(machine& machine) : machine_(machine) {}

  target_status set_breakpoint(const breakpoint_spec& request) {
    if (!supports(request.type)) {
      return target_status::unsupported;
    }
    machine_.add_breakpoint(request);
    return target_status::ok;
  }

  target_status remove_breakpoint(const breakpoint_spec& request) {
    if (!supports(request.type)) {
      return target_status::unsupported;
    }
    machine_.remove_breakpoint(request);
    return target_status::ok;
  }

  breakpoint_capabilities capabilities() const {
    breakpoint_capabilities caps;
    caps.software = true;
    caps.hardware = true;
    caps.watch_read = true;
    caps.watch_write = true;
    caps.watch_access = true;
    return caps;
  }

private:
  static bool supports(breakpoint_type type) {
    switch (type) {
      case breakpoint_type::software:
      case breakpoint_type::hardware:
      case breakpoint_type::watch_read:
      case breakpoint_type::watch_write:
      case breakpoint_type::watch_access:
        return true;
    }
    return false;
  }

  machine& machine_;
};

class threads_component {
public:
  threads_component(threads& threads, machine& machine, runner& runner)
      : threads_(threads), machine_(machine), runner_(runner) {}

  std::vector<uint64_t> thread_ids() { return threads_.ids(); }

  uint64_t current_thread() const { return threads_.current_thread(); }

  target_status set_current_thread(uint64_t tid) { return threads_.set_current_thread(tid); }

  std::optional<uint64_t> thread_pc(uint64_t tid) {
    if (tid == threads_.current_thread()) {
      return machine_.pc();
    }
    return std::nullopt;
  }

  std::optional<std::string> thread_name(uint64_t tid) {
    if (tid == threads_.current_thread()) {
      return std::string("toy-thread");
    }
    return std::nullopt;
  }

  std::optional<stop_reason> thread_stop_reason(uint64_t tid) {
    if (tid == threads_.current_thread()) {
      return runner_.last_stop();
    }
    return std::nullopt;
  }

private:
  threads& threads_;
  machine& machine_;
  runner& runner_;
};

class memory_layout_component {
public:
  explicit memory_layout_component(machine& machine) : machine_(machine) {}

  std::optional<memory_region_info> region_info(uint64_t addr) {
    auto regions = memory_map();
    return region_info_from_map(regions, addr);
  }

  std::vector<memory_region> memory_map() {
    return {memory_region{
        0,
        static_cast<uint64_t>(machine_.memory_size()),
        mem_perm::read | mem_perm::write | mem_perm::exec
    }};
  }

private:
  machine& machine_;
};

class host_component {
public:
  explicit host_component(const config& cfg) : config_(cfg) {}

  std::optional<host_info> get_host_info() {
    host_info info;
    info.triple = config_.triple;
    info.endian = config_.endian;
    info.ptr_size = static_cast<int>(config_.reg_bits / 8);
    info.hostname = config_.hostname;
    return info;
  }

private:
  const config& config_;
};

class process_component {
public:
  explicit process_component(const config& cfg) : config_(cfg) {}

  std::optional<process_info> get_process_info() {
    process_info info;
    info.pid = config_.pid;
    info.triple = config_.triple;
    info.endian = config_.endian;
    info.ptr_size = static_cast<int>(config_.reg_bits / 8);
    info.ostype = config_.osabi;
    return info;
  }

private:
  const config& config_;
};

class shlib_component {
public:
  explicit shlib_component(const config& cfg) : config_(cfg) {}

  std::optional<shlib_info> get_shlib_info() {
    if (!config_.shlib_info_addr) {
      return std::nullopt;
    }
    shlib_info info;
    info.info_addr = config_.shlib_info_addr;
    return info;
  }

private:
  const config& config_;
};

} // namespace detail

// Canonical toy target composed from small capability components.
class target final {
public:
  explicit target(config cfg)
      : config_(std::move(cfg)),
        layout_(config_),
        machine_(config_),
        threads_(config_.thread_ids),
        runner_(machine_, threads_, config_.mode, config_.max_steps, config_.history_limit),
        regs_(layout_, machine_),
        reg_info_(layout_),
        mem_(machine_),
        run_(runner_),
        breakpoints_(machine_),
        thread_api_(threads_, machine_, runner_),
        memory_layout_(machine_),
        host_(config_),
        process_(config_),
        shlib_(config_) {}

  const layout& layout_spec() const { return layout_; }

  gdbstub::arch_spec make_arch_spec() const {
    arch_spec spec;
    spec.target_xml = layout_.target_xml();
    spec.xml_arch_name = layout_.xml_arch_name();
    spec.osabi = config_.osabi;
    spec.reg_count = layout_.reg_count();
    spec.pc_reg_num = layout_.pc_reg_num();
    spec.address_bits = static_cast<int>(config_.reg_bits);
    return spec;
  }

  gdbstub::target make_target() {
    return gdbstub::make_target(
        regs_,
        mem_,
        run_,
        breakpoints_,
        thread_api_,
        memory_layout_,
        host_,
        process_,
        shlib_,
        reg_info_
    );
  }

  void set_mode(execution_mode mode) {
    config_.mode = mode;
    runner_.set_mode(mode);
  }

  void set_reg(int regno, uint64_t value) { machine_.set_reg(regno, value); }
  uint64_t reg_value(int regno) const { return machine_.reg_value(regno); }

private:
  config config_;
  layout layout_;
  machine machine_;
  threads threads_;
  runner runner_;
  detail::regs_component regs_;
  detail::register_info_component reg_info_;
  detail::mem_component mem_;
  detail::run_component run_;
  detail::breakpoints_component breakpoints_;
  detail::threads_component thread_api_;
  detail::memory_layout_component memory_layout_;
  detail::host_component host_;
  detail::process_component process_;
  detail::shlib_component shlib_;
};

} // namespace gdbstub::toy
