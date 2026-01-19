#include "gdbstub_cpp_c.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gdbstub/gdbstub.hpp"
#include "gdbstub/server.hpp"
#include "gdbstub/target.hpp"
#include "gdbstub/transport.hpp"
#include "gdbstub/transport_tcp.hpp"

namespace gdbstub_c_detail {

std::string to_string(gdbstub_string_view view) {
  if (!view.data || view.size == 0) {
    return {};
  }
  return std::string(view.data, view.size);
}

template <typename T>
std::optional<T> opt_value(bool has_value, T value) {
  if (!has_value) {
    return std::nullopt;
  }
  return value;
}

gdbstub::mem_perm to_mem_perm(uint8_t value) {
  return static_cast<gdbstub::mem_perm>(value);
}

struct c_target;
extern "C" void gdbstub_stop_notify_tramp(void* ctx, const gdbstub_stop_reason* reason);

gdbstub::stop_reason to_stop_reason(const gdbstub_stop_reason& in) {
  gdbstub::stop_reason out;
  out.kind = static_cast<gdbstub::stop_kind>(in.kind);
  out.signal = in.signal;
  out.addr = in.addr;
  out.exit_code = in.exit_code;
  if (in.has_thread_id) {
    out.thread_id = in.thread_id;
  }
  if (in.has_replay_log) {
    out.replay_log = static_cast<gdbstub::replay_log_boundary>(in.replay_log);
  }
  return out;
}

gdbstub::resume_request to_resume_request(const gdbstub_resume_request& in) {
  gdbstub::resume_request out;
  out.action = static_cast<gdbstub::resume_action>(in.action);
  out.direction = static_cast<gdbstub::resume_direction>(in.direction);
  if (in.has_addr) {
    out.addr = in.addr;
  }
  if (in.has_signal) {
    out.signal = in.signal;
  }
  if (in.has_range) {
    gdbstub::address_range range;
    range.start = in.range.start;
    range.end = in.range.end;
    out.range = range;
  }
  return out;
}

gdbstub::resume_result to_resume_result(const gdbstub_resume_result& in) {
  gdbstub::resume_result out;
  out.state = static_cast<decltype(out.state)>(in.state);
  out.stop = to_stop_reason(in.stop);
  out.exit_code = in.exit_code;
  out.status = static_cast<gdbstub::target_status>(in.status);
  return out;
}

gdbstub::run_capabilities to_run_capabilities(const gdbstub_run_capabilities& caps) {
  gdbstub::run_capabilities out;
  out.reverse_continue = caps.reverse_continue != 0;
  out.reverse_step = caps.reverse_step != 0;
  out.range_step = caps.range_step != 0;
  out.non_stop = caps.non_stop != 0;
  return out;
}

gdbstub::breakpoint_capabilities to_breakpoint_capabilities(const gdbstub_breakpoint_capabilities& caps) {
  gdbstub::breakpoint_capabilities out;
  out.software = caps.software != 0;
  out.hardware = caps.hardware != 0;
  out.watch_read = caps.watch_read != 0;
  out.watch_write = caps.watch_write != 0;
  out.watch_access = caps.watch_access != 0;
  return out;
}

gdbstub_stop_reason to_c_stop_reason(const gdbstub::stop_reason& in) {
  gdbstub_stop_reason out{};
  out.kind = static_cast<gdbstub_stop_kind>(in.kind);
  out.signal = in.signal;
  out.addr = in.addr;
  out.exit_code = in.exit_code;
  out.has_thread_id = in.thread_id.has_value() ? 1 : 0;
  out.thread_id = in.thread_id.value_or(0);
  out.has_replay_log = in.replay_log.has_value() ? 1 : 0;
  out.replay_log = in.replay_log ? static_cast<gdbstub_replay_log_boundary>(*in.replay_log)
                                 : GDBSTUB_REPLAY_LOG_BEGIN;
  return out;
}

gdbstub_resume_result to_c_resume_result(const gdbstub::resume_result& in) {
  gdbstub_resume_result out{};
  out.state = static_cast<gdbstub_resume_state>(in.state);
  out.stop = to_c_stop_reason(in.stop);
  out.exit_code = in.exit_code;
  out.status = static_cast<gdbstub_target_status>(in.status);
  return out;
}

gdbstub::breakpoint_spec to_breakpoint_spec(const gdbstub_breakpoint_spec& spec) {
  gdbstub::breakpoint_spec out;
  out.type = static_cast<gdbstub::breakpoint_type>(spec.type);
  out.addr = spec.addr;
  out.length = spec.length;
  return out;
}

gdbstub::memory_region to_memory_region(const gdbstub_memory_region& region) {
  gdbstub::memory_region out;
  out.start = region.start;
  out.size = region.size;
  out.perms = to_mem_perm(region.perms);
  if (region.has_name) {
    out.name = to_string(region.name);
  }
  out.types.reserve(region.types.len);
  if (region.types.data) {
    for (size_t i = 0; i < region.types.len; ++i) {
      out.types.push_back(to_string(region.types.data[i]));
    }
  }
  return out;
}

gdbstub::memory_region_info to_memory_region_info(const gdbstub_memory_region_info& info) {
  gdbstub::memory_region_info out;
  out.start = info.start;
  out.size = info.size;
  out.mapped = info.mapped != 0;
  out.perms = to_mem_perm(info.perms);
  if (info.has_name) {
    out.name = to_string(info.name);
  }
  out.types.reserve(info.types.len);
  if (info.types.data) {
    for (size_t i = 0; i < info.types.len; ++i) {
      out.types.push_back(to_string(info.types.data[i]));
    }
  }
  return out;
}

gdbstub::host_info to_host_info(const gdbstub_host_info& info) {
  gdbstub::host_info out;
  out.triple = to_string(info.triple);
  out.endian = to_string(info.endian);
  out.ptr_size = info.ptr_size;
  out.hostname = to_string(info.hostname);
  out.os_version = opt_value(info.has_os_version != 0, to_string(info.os_version));
  out.os_build = opt_value(info.has_os_build != 0, to_string(info.os_build));
  out.os_kernel = opt_value(info.has_os_kernel != 0, to_string(info.os_kernel));
  out.addressing_bits = opt_value(info.has_addressing_bits != 0, info.addressing_bits);
  return out;
}

gdbstub::process_info to_process_info(const gdbstub_process_info& info) {
  gdbstub::process_info out;
  out.pid = info.pid;
  out.triple = to_string(info.triple);
  out.endian = to_string(info.endian);
  out.ptr_size = info.ptr_size;
  out.ostype = to_string(info.ostype);
  return out;
}

gdbstub::shlib_info to_shlib_info(const gdbstub_shlib_info& info) {
  gdbstub::shlib_info out;
  out.info_addr = opt_value(info.has_info_addr != 0, info.info_addr);
  return out;
}

gdbstub::offsets_info to_offsets_info(const gdbstub_offsets_info& info) {
  gdbstub::offsets_info out;
  out.kind = info.kind == GDBSTUB_OFFSETS_SEGMENT ? gdbstub::offsets_kind::segment
                                                  : gdbstub::offsets_kind::section;
  out.text = info.text;
  out.data = opt_value(info.has_data != 0, info.data);
  out.bss = opt_value(info.has_bss != 0, info.bss);
  return out;
}

gdbstub::register_info to_register_info(const gdbstub_register_info& info) {
  gdbstub::register_info out;
  out.name = to_string(info.name);
  out.alt_name = opt_value(info.has_alt_name != 0, to_string(info.alt_name));
  out.bitsize = info.bitsize;
  out.offset = opt_value(info.has_offset != 0, static_cast<size_t>(info.offset));
  out.encoding = to_string(info.encoding);
  out.format = to_string(info.format);
  out.set = opt_value(info.has_set != 0, to_string(info.set));
  out.gcc_regnum = opt_value(info.has_gcc_regnum != 0, info.gcc_regnum);
  out.dwarf_regnum = opt_value(info.has_dwarf_regnum != 0, info.dwarf_regnum);
  out.generic = opt_value(info.has_generic != 0, to_string(info.generic));
  if (info.container_regs.data && info.container_regs.len > 0) {
    out.container_regs.assign(info.container_regs.data, info.container_regs.data + info.container_regs.len);
  }
  if (info.invalidate_regs.data && info.invalidate_regs.len > 0) {
    out.invalidate_regs.assign(info.invalidate_regs.data, info.invalidate_regs.data + info.invalidate_regs.len);
  }
  return out;
}

gdbstub::arch_spec to_arch_spec(const gdbstub_arch_spec& spec) {
  gdbstub::arch_spec out;
  out.target_xml = to_string(spec.target_xml);
  out.xml_arch_name = to_string(spec.xml_arch_name);
  out.osabi = to_string(spec.osabi);
  out.reg_count = spec.reg_count;
  out.pc_reg_num = spec.pc_reg_num;
  out.address_bits = opt_value(spec.has_address_bits != 0, spec.address_bits);
  out.swap_register_endianness = spec.swap_register_endianness != 0;
  return out;
}

struct c_target {
  gdbstub_regs_iface regs{};
  gdbstub_mem_iface mem{};
  gdbstub_run_iface run{};
  std::optional<gdbstub_breakpoints_iface> breakpoints;
  std::optional<gdbstub_memory_layout_iface> memory_layout;
  std::optional<gdbstub_threads_iface> threads;
  std::optional<gdbstub_host_info_iface> host;
  std::optional<gdbstub_process_info_iface> process;
  std::optional<gdbstub_shlib_info_iface> shlib;
  std::optional<gdbstub_process_control_iface> process_control;
  std::optional<gdbstub_offsets_info_iface> offsets;
  std::optional<gdbstub_register_info_iface> reg_info;
  std::optional<gdbstub::stop_notifier> stop_notifier;

  explicit c_target(const gdbstub_target_config& config)
      : regs(config.regs), mem(config.mem), run(config.run) {
    if (config.breakpoints) {
      breakpoints = *config.breakpoints;
    }
    if (config.memory_layout) {
      memory_layout = *config.memory_layout;
    }
    if (config.threads) {
      threads = *config.threads;
    }
    if (config.host) {
      host = *config.host;
    }
    if (config.process) {
      process = *config.process;
    }
    if (config.shlib) {
      shlib = *config.shlib;
    }
    if (config.process_control) {
      process_control = *config.process_control;
    }
    if (config.offsets) {
      offsets = *config.offsets;
    }
    if (config.reg_info) {
      reg_info = *config.reg_info;
    }
  }

  static size_t reg_size_tramp(void* ctx, int regno) {
    auto* self = static_cast<c_target*>(ctx);
    return self->regs.reg_size(self->regs.ctx, regno);
  }

  static gdbstub::target_status read_reg_tramp(void* ctx, int regno, std::span<std::byte> out) {
    auto* self = static_cast<c_target*>(ctx);
    return static_cast<gdbstub::target_status>(self->regs.read_reg(
        self->regs.ctx,
        regno,
        reinterpret_cast<uint8_t*>(out.data()),
        out.size()
    ));
  }

  static gdbstub::target_status write_reg_tramp(
      void* ctx,
      int regno,
      std::span<const std::byte> data
  ) {
    auto* self = static_cast<c_target*>(ctx);
    return static_cast<gdbstub::target_status>(self->regs.write_reg(
        self->regs.ctx,
        regno,
        reinterpret_cast<const uint8_t*>(data.data()),
        data.size()
    ));
  }

  static gdbstub::target_status read_mem_tramp(
      void* ctx,
      uint64_t addr,
      std::span<std::byte> out
  ) {
    auto* self = static_cast<c_target*>(ctx);
    return static_cast<gdbstub::target_status>(self->mem.read_mem(
        self->mem.ctx,
        addr,
        reinterpret_cast<uint8_t*>(out.data()),
        out.size()
    ));
  }

  static gdbstub::target_status write_mem_tramp(
      void* ctx,
      uint64_t addr,
      std::span<const std::byte> data
  ) {
    auto* self = static_cast<c_target*>(ctx);
    return static_cast<gdbstub::target_status>(self->mem.write_mem(
        self->mem.ctx,
        addr,
        reinterpret_cast<const uint8_t*>(data.data()),
        data.size()
    ));
  }

  static gdbstub::resume_result resume_tramp(void* ctx, const gdbstub::resume_request& request) {
    auto* self = static_cast<c_target*>(ctx);
    gdbstub_address_range range{};
    if (request.range) {
      range.start = request.range->start;
      range.end = request.range->end;
    }
    const auto c_request = gdbstub_resume_request{
        static_cast<gdbstub_resume_action>(request.action),
        static_cast<gdbstub_resume_direction>(request.direction),
        static_cast<uint8_t>(request.addr.has_value() ? 1 : 0),
        request.addr.value_or(0),
        static_cast<uint8_t>(request.signal.has_value() ? 1 : 0),
        request.signal.value_or(0),
        static_cast<uint8_t>(request.range.has_value() ? 1 : 0),
        range,
    };
    const auto result = self->run.resume(self->run.ctx, &c_request);
    return to_resume_result(result);
  }

  static void interrupt_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    if (self->run.interrupt) {
      self->run.interrupt(self->run.ctx);
    }
  }

  static std::optional<gdbstub::stop_reason> poll_stop_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->run.poll_stop) {
      return std::nullopt;
    }
    gdbstub_stop_reason reason{};
    if (!self->run.poll_stop(self->run.ctx, &reason)) {
      return std::nullopt;
    }
    return to_stop_reason(reason);
  }

  static void set_stop_notifier_tramp(void* ctx, gdbstub::stop_notifier notifier) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->run.set_stop_notifier) {
      return;
    }
    self->stop_notifier = notifier;
    gdbstub_stop_notifier c_notifier{};
    c_notifier.ctx = self;
    c_notifier.notify = &gdbstub_stop_notify_tramp;
    self->run.set_stop_notifier(self->run.ctx, c_notifier);
  }

  static std::optional<gdbstub::run_capabilities> run_capabilities_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->run.get_capabilities) {
      return std::nullopt;
    }
    gdbstub_run_capabilities caps{};
    if (!self->run.get_capabilities(self->run.ctx, &caps)) {
      return std::nullopt;
    }
    return to_run_capabilities(caps);
  }

  static gdbstub::target_status set_breakpoint_tramp(void* ctx, const gdbstub::breakpoint_spec& spec) {
    auto* self = static_cast<c_target*>(ctx);
    const auto c_spec = gdbstub_breakpoint_spec{
        static_cast<gdbstub_breakpoint_type>(spec.type),
        spec.addr,
        spec.length,
    };
    return static_cast<gdbstub::target_status>(
        self->breakpoints->set_breakpoint(self->breakpoints->ctx, &c_spec)
    );
  }

  static gdbstub::target_status remove_breakpoint_tramp(void* ctx, const gdbstub::breakpoint_spec& spec) {
    auto* self = static_cast<c_target*>(ctx);
    const auto c_spec = gdbstub_breakpoint_spec{
        static_cast<gdbstub_breakpoint_type>(spec.type),
        spec.addr,
        spec.length,
    };
    return static_cast<gdbstub::target_status>(
        self->breakpoints->remove_breakpoint(self->breakpoints->ctx, &c_spec)
    );
  }

  static std::optional<gdbstub::breakpoint_capabilities> breakpoint_capabilities_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->breakpoints || !self->breakpoints->get_capabilities) {
      return std::nullopt;
    }
    gdbstub_breakpoint_capabilities caps{};
    if (!self->breakpoints->get_capabilities(self->breakpoints->ctx, &caps)) {
      return std::nullopt;
    }
    return to_breakpoint_capabilities(caps);
  }

  static std::optional<gdbstub::memory_region_info> region_info_tramp(void* ctx, uint64_t addr) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->memory_layout || !self->memory_layout->region_info) {
      return std::nullopt;
    }
    gdbstub_memory_region_info info{};
    if (!self->memory_layout->region_info(self->memory_layout->ctx, addr, &info)) {
      return std::nullopt;
    }
    return to_memory_region_info(info);
  }

  static std::vector<gdbstub::memory_region> memory_map_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->memory_layout || !self->memory_layout->memory_map) {
      return {};
    }
    const auto regions = self->memory_layout->memory_map(self->memory_layout->ctx);
    std::vector<gdbstub::memory_region> out;
    out.reserve(regions.len);
    if (!regions.data || regions.len == 0) {
      return out;
    }
    for (size_t i = 0; i < regions.len; ++i) {
      out.push_back(to_memory_region(regions.data[i]));
    }
    return out;
  }

  static std::vector<uint64_t> thread_ids_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    const auto ids = self->threads->thread_ids(self->threads->ctx);
    if (!ids.data || ids.len == 0) {
      return {};
    }
    return std::vector<uint64_t>(ids.data, ids.data + ids.len);
  }

  static uint64_t current_thread_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    return self->threads->current_thread(self->threads->ctx);
  }

  static gdbstub::target_status set_current_thread_tramp(void* ctx, uint64_t tid) {
    auto* self = static_cast<c_target*>(ctx);
    return static_cast<gdbstub::target_status>(self->threads->set_current_thread(self->threads->ctx, tid));
  }

  static std::optional<uint64_t> thread_pc_tramp(void* ctx, uint64_t tid) {
    auto* self = static_cast<c_target*>(ctx);
    uint64_t value = 0;
    if (!self->threads->thread_pc(self->threads->ctx, tid, &value)) {
      return std::nullopt;
    }
    return value;
  }

  static std::optional<std::string> thread_name_tramp(void* ctx, uint64_t tid) {
    auto* self = static_cast<c_target*>(ctx);
    gdbstub_string_view name{};
    if (!self->threads->thread_name(self->threads->ctx, tid, &name)) {
      return std::nullopt;
    }
    return to_string(name);
  }

  static std::optional<gdbstub::stop_reason> thread_stop_reason_tramp(void* ctx, uint64_t tid) {
    auto* self = static_cast<c_target*>(ctx);
    gdbstub_stop_reason reason{};
    if (!self->threads->thread_stop_reason(self->threads->ctx, tid, &reason)) {
      return std::nullopt;
    }
    return to_stop_reason(reason);
  }

  static std::optional<gdbstub::host_info> host_info_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    gdbstub_host_info info{};
    if (!self->host->get_host_info(self->host->ctx, &info)) {
      return std::nullopt;
    }
    return to_host_info(info);
  }

  static std::optional<gdbstub::process_info> process_info_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    gdbstub_process_info info{};
    if (!self->process->get_process_info(self->process->ctx, &info)) {
      return std::nullopt;
    }
    return to_process_info(info);
  }

  static std::optional<gdbstub::shlib_info> shlib_info_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    gdbstub_shlib_info info{};
    if (!self->shlib->get_shlib_info(self->shlib->ctx, &info)) {
      return std::nullopt;
    }
    return to_shlib_info(info);
  }

  static std::optional<gdbstub::resume_result> launch_tramp(
      void* ctx,
      const gdbstub::process_launch_request& request
  ) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->process_control || !self->process_control->launch) {
      return std::nullopt;
    }
    gdbstub_process_launch_request c_request{};
    gdbstub_string_view filename{};
    if (request.filename) {
      c_request.has_filename = 1;
      filename.data = request.filename->data();
      filename.size = request.filename->size();
    } else {
      c_request.has_filename = 0;
    }
    c_request.filename = filename;
    std::vector<gdbstub_string_view> arg_views;
    arg_views.reserve(request.args.size());
    for (const auto& arg : request.args) {
      gdbstub_string_view view{};
      view.data = arg.data();
      view.size = arg.size();
      arg_views.push_back(view);
    }
    c_request.args = arg_views.data();
    c_request.args_len = arg_views.size();
    auto result = self->process_control->launch(self->process_control->ctx, &c_request);
    return to_resume_result(result);
  }

  static std::optional<gdbstub::resume_result> attach_tramp(void* ctx, uint64_t pid) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->process_control || !self->process_control->attach) {
      return std::nullopt;
    }
    auto result = self->process_control->attach(self->process_control->ctx, pid);
    return to_resume_result(result);
  }

  static gdbstub::target_status kill_tramp(void* ctx, std::optional<uint64_t> pid) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->process_control || !self->process_control->kill) {
      return gdbstub::target_status::unsupported;
    }
    auto status = self->process_control->kill(self->process_control->ctx, pid.has_value() ? 1 : 0, pid.value_or(0));
    return static_cast<gdbstub::target_status>(status);
  }

  static std::optional<gdbstub::resume_result> restart_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    if (!self->process_control || !self->process_control->restart) {
      return std::nullopt;
    }
    auto result = self->process_control->restart(self->process_control->ctx);
    return to_resume_result(result);
  }

  static std::optional<gdbstub::offsets_info> offsets_info_tramp(void* ctx) {
    auto* self = static_cast<c_target*>(ctx);
    gdbstub_offsets_info info{};
    if (!self->offsets->get_offsets_info(self->offsets->ctx, &info)) {
      return std::nullopt;
    }
    return to_offsets_info(info);
  }

  static std::optional<gdbstub::register_info> register_info_tramp(void* ctx, int regno) {
    auto* self = static_cast<c_target*>(ctx);
    gdbstub_register_info info{};
    if (!self->reg_info->get_register_info(self->reg_info->ctx, regno, &info)) {
      return std::nullopt;
    }
    return to_register_info(info);
  }

  gdbstub::target_view make_view() {
    gdbstub::target_view view;
    view.regs.ctx = this;
    view.regs.reg_size_fn = &reg_size_tramp;
    view.regs.read_reg_fn = &read_reg_tramp;
    view.regs.write_reg_fn = &write_reg_tramp;

    view.mem.ctx = this;
    view.mem.read_mem_fn = &read_mem_tramp;
    view.mem.write_mem_fn = &write_mem_tramp;

    view.run.ctx = this;
    view.run.resume_fn = [](void* ctx, const gdbstub::resume_request& request) -> gdbstub::resume_result {
      return resume_tramp(ctx, request);
    };
    view.run.interrupt_fn = run.interrupt ? &interrupt_tramp : nullptr;
    view.run.poll_stop_fn = run.poll_stop ? &poll_stop_tramp : nullptr;
    view.run.set_stop_notifier_fn = run.set_stop_notifier ? &set_stop_notifier_tramp : nullptr;
    view.run.get_run_capabilities_fn = run.get_capabilities ? &run_capabilities_tramp : nullptr;

    if (breakpoints) {
      gdbstub::breakpoints_view bp;
      bp.ctx = this;
      bp.set_breakpoint_fn = &set_breakpoint_tramp;
      bp.remove_breakpoint_fn = &remove_breakpoint_tramp;
      bp.get_breakpoint_capabilities_fn = breakpoints->get_capabilities ? &breakpoint_capabilities_tramp : nullptr;
      view.breakpoints = bp;
    }

    if (memory_layout) {
      gdbstub::memory_layout_view layout;
      layout.ctx = this;
      layout.region_info_fn = memory_layout->region_info ? &region_info_tramp : nullptr;
      layout.memory_map_fn = memory_layout->memory_map ? &memory_map_tramp : nullptr;
      view.memory_layout = layout;
    }

    if (threads) {
      gdbstub::threads_view th;
      th.ctx = this;
      th.thread_ids_fn = &thread_ids_tramp;
      th.current_thread_fn = &current_thread_tramp;
      th.set_current_thread_fn = &set_current_thread_tramp;
      th.thread_pc_fn = &thread_pc_tramp;
      th.thread_name_fn = &thread_name_tramp;
      th.thread_stop_reason_fn = &thread_stop_reason_tramp;
      view.threads = th;
    }

    if (host) {
      gdbstub::host_info_view hv;
      hv.ctx = this;
      hv.get_host_info_fn = &host_info_tramp;
      view.host = hv;
    }

    if (process) {
      gdbstub::process_info_view pv;
      pv.ctx = this;
      pv.get_process_info_fn = &process_info_tramp;
      view.process = pv;
    }

    if (shlib) {
      gdbstub::shlib_view sv;
      sv.ctx = this;
      sv.get_shlib_info_fn = &shlib_info_tramp;
      view.shlib = sv;
    }

    if (process_control) {
      gdbstub::process_control_view pv;
      pv.ctx = this;
      pv.launch_fn = &launch_tramp;
      pv.attach_fn = &attach_tramp;
      pv.kill_fn = &kill_tramp;
      pv.restart_fn = &restart_tramp;
      view.process_control = pv;
    }

    if (offsets) {
      gdbstub::offsets_view ov;
      ov.ctx = this;
      ov.get_offsets_info_fn = &offsets_info_tramp;
      view.offsets = ov;
    }

    if (reg_info) {
      gdbstub::register_info_view rv;
      rv.ctx = this;
      rv.get_register_info_fn = &register_info_tramp;
      view.reg_info = rv;
    }

    return view;
  }
};

extern "C" void gdbstub_stop_notify_tramp(void* ctx, const gdbstub_stop_reason* reason) {
  auto* self = static_cast<c_target*>(ctx);
  if (!self || !self->stop_notifier || !reason) {
    return;
  }
  self->stop_notifier->notify(self->stop_notifier->ctx, to_stop_reason(*reason));
}

} // namespace gdbstub_c_detail

struct gdbstub_target {
  gdbstub_c_detail::c_target impl;
  gdbstub::target target;

  explicit gdbstub_target(const gdbstub_target_config& config)
      : impl(config), target(impl.make_view()) {}
};

struct gdbstub_transport {
  std::unique_ptr<gdbstub::transport> impl;
};

struct gdbstub_server {
  std::unique_ptr<gdbstub::server> impl;
};

using namespace gdbstub_c_detail;

extern "C" gdbstub_string_view gdbstub_version(void) {
  auto view = gdbstub::version();
  gdbstub_string_view out{};
  out.data = view.data();
  out.size = view.size();
  return out;
}

extern "C" gdbstub_transport* gdbstub_transport_tcp_create(void) {
  auto transport = std::make_unique<gdbstub_transport>();
  transport->impl = std::make_unique<gdbstub::transport_tcp>();
  return transport.release();
}

extern "C" void gdbstub_transport_destroy(gdbstub_transport* transport) {
  delete transport;
}

extern "C" gdbstub_target* gdbstub_target_create(const gdbstub_target_config* config) {
  if (!config) {
    return nullptr;
  }
  if (!config->regs.reg_size || !config->regs.read_reg || !config->regs.write_reg) {
    return nullptr;
  }
  if (!config->mem.read_mem || !config->mem.write_mem) {
    return nullptr;
  }
  if (!config->run.resume) {
    return nullptr;
  }
  return new gdbstub_target(*config);
}

extern "C" void gdbstub_target_destroy(gdbstub_target* target) {
  delete target;
}

extern "C" gdbstub_server* gdbstub_server_create(
    gdbstub_target* target,
    gdbstub_arch_spec arch,
    gdbstub_transport* transport
) {
  if (!target || !transport || !transport->impl) {
    return nullptr;
  }
  auto server = std::make_unique<gdbstub_server>();
  auto transport_ptr = std::move(transport->impl);
  delete transport;
  server->impl = std::make_unique<gdbstub::server>(target->target, to_arch_spec(arch), std::move(transport_ptr));
  return server.release();
}

extern "C" void gdbstub_server_destroy(gdbstub_server* server) {
  delete server;
}

extern "C" uint8_t gdbstub_server_listen(gdbstub_server* server, gdbstub_string_view address) {
  if (!server || !server->impl) {
    return 0;
  }
  return server->impl->listen(std::string_view(address.data, address.size)) ? 1 : 0;
}

extern "C" uint8_t gdbstub_server_wait_for_connection(gdbstub_server* server) {
  if (!server || !server->impl) {
    return 0;
  }
  return server->impl->wait_for_connection() ? 1 : 0;
}

extern "C" uint8_t gdbstub_server_has_connection(gdbstub_server* server) {
  if (!server || !server->impl) {
    return 0;
  }
  return server->impl->has_connection() ? 1 : 0;
}

extern "C" void gdbstub_server_serve_forever(gdbstub_server* server) {
  if (!server || !server->impl) {
    return;
  }
  server->impl->serve_forever();
}

extern "C" uint8_t gdbstub_server_poll(gdbstub_server* server, uint64_t timeout_ms) {
  if (!server || !server->impl) {
    return 0;
  }
  return server->impl->poll(std::chrono::milliseconds(timeout_ms)) ? 1 : 0;
}

extern "C" void gdbstub_server_notify_stop(gdbstub_server* server, const gdbstub_stop_reason* reason) {
  if (!server || !server->impl || !reason) {
    return;
  }
  server->impl->notify_stop(to_stop_reason(*reason));
}

extern "C" void gdbstub_server_stop(gdbstub_server* server) {
  if (!server || !server->impl) {
    return;
  }
  server->impl->stop();
}
