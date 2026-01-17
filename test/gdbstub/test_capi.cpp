#include "doctest/doctest.hpp"

#include "gdbstub/tcp_test_client.hpp"
#include "gdbstub_cpp_c.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

namespace {

constexpr int k_reg_count = 4;
constexpr size_t k_reg_size = 4;
constexpr uint64_t k_mem_base = 0x1000;
constexpr size_t k_mem_size = 0x100;

struct capi_state {
  uint8_t regs[k_reg_count * k_reg_size]{};
  uint8_t mem[k_mem_size]{};
  uint64_t threads[2]{1, 2};
  uint64_t current_thread = 1;

  bool resume_running = false;
  bool running = false;
  bool has_notifier = false;
  bool enable_poll_stop = true;
  bool enable_stop_notifier = true;
  gdbstub_stop_notifier notifier{};

  size_t breakpoints_set = 0;
  size_t breakpoints_removed = 0;

  gdbstub_memory_region region{};
  gdbstub_string_view region_types[1]{};
  gdbstub_slice_string region_type_slice{};

  gdbstub_memory_region_info region_info{};

  gdbstub_host_info host{};
  gdbstub_process_info process{};
  gdbstub_shlib_info shlib{};

  gdbstub_register_info reg_info{};
  gdbstub_slice_int reg_info_container_slice{};
  gdbstub_slice_int reg_info_invalidate_slice{};
  int reg_info_container_data[2]{};
  int reg_info_invalidate_data[1]{};

  gdbstub_string_view thread_names[2]{};

  gdbstub_regs_iface regs_iface{};
  gdbstub_mem_iface mem_iface{};
  gdbstub_run_iface run_iface{};
  gdbstub_breakpoints_iface bp_iface{};
  gdbstub_memory_layout_iface layout_iface{};
  gdbstub_threads_iface threads_iface{};
  gdbstub_host_info_iface host_iface{};
  gdbstub_process_info_iface process_iface{};
  gdbstub_shlib_info_iface shlib_iface{};
  gdbstub_register_info_iface reg_info_iface{};
  gdbstub_target_config config{};
};

static gdbstub_string_view make_view(const char* text) {
  gdbstub_string_view view{};
  view.data = text;
  view.size = std::strlen(text);
  return view;
}

static void init_state(capi_state& state) {
  std::memset(state.regs, 0, sizeof(state.regs));
  std::memset(state.mem, 0, sizeof(state.mem));
  for (size_t i = 0; i < k_mem_size; ++i) {
    state.mem[i] = static_cast<uint8_t>(i & 0xff);
  }

  state.regs[4] = 0x11;
  state.regs[5] = 0x22;
  state.regs[6] = 0x33;
  state.regs[7] = 0x44;

  const char* region_name = "ram";
  state.region.start = k_mem_base;
  state.region.size = k_mem_size;
  state.region.perms = static_cast<uint8_t>(GDBSTUB_MEM_PERM_READ | GDBSTUB_MEM_PERM_WRITE);
  state.region.has_name = 1;
  state.region.name = make_view(region_name);
  state.region_types[0] = make_view("ram");
  state.region_type_slice.data = state.region_types;
  state.region_type_slice.len = 1;
  state.region.types = state.region_type_slice;

  state.region_info.start = k_mem_base;
  state.region_info.size = k_mem_size;
  state.region_info.mapped = 1;
  state.region_info.perms = static_cast<uint8_t>(GDBSTUB_MEM_PERM_READ | GDBSTUB_MEM_PERM_WRITE);
  state.region_info.has_name = 1;
  state.region_info.name = make_view(region_name);
  state.region_info.types = state.region_type_slice;

  state.host.triple = make_view("riscv32-unknown-elf");
  state.host.endian = make_view("little");
  state.host.ptr_size = 4;
  state.host.hostname = make_view("capi-target");
  state.host.has_os_version = 1;
  state.host.os_version = make_view("1.0");
  state.host.has_os_build = 1;
  state.host.os_build = make_view("capi");
  state.host.has_os_kernel = 1;
  state.host.os_kernel = make_view("capi-kernel");
  state.host.has_addressing_bits = 1;
  state.host.addressing_bits = 32;

  state.process.pid = 1234;
  state.process.triple = make_view("riscv32-unknown-elf");
  state.process.endian = make_view("little");
  state.process.ptr_size = 4;
  state.process.ostype = make_view("bare");

  state.shlib.has_info_addr = 1;
  state.shlib.info_addr = 0x11223344;

  state.reg_info.name = make_view("r0");
  state.reg_info.has_alt_name = 1;
  state.reg_info.alt_name = make_view("zero");
  state.reg_info.bitsize = static_cast<int>(k_reg_size * 8);
  state.reg_info.has_offset = 1;
  state.reg_info.offset = 0;
  state.reg_info.encoding = make_view("uint");
  state.reg_info.format = make_view("hex");
  state.reg_info.has_set = 1;
  state.reg_info.set = make_view("general");
  state.reg_info.has_gcc_regnum = 1;
  state.reg_info.gcc_regnum = 0;
  state.reg_info.has_dwarf_regnum = 1;
  state.reg_info.dwarf_regnum = 0;
  state.reg_info.has_generic = 1;
  state.reg_info.generic = make_view("arg1");
  state.reg_info_container_data[0] = 1;
  state.reg_info_container_data[1] = 2;
  state.reg_info_invalidate_data[0] = 3;
  state.reg_info_container_slice.data = state.reg_info_container_data;
  state.reg_info_container_slice.len = 2;
  state.reg_info_invalidate_slice.data = state.reg_info_invalidate_data;
  state.reg_info_invalidate_slice.len = 1;
  state.reg_info.container_regs = state.reg_info_container_slice;
  state.reg_info.invalidate_regs = state.reg_info_invalidate_slice;

  state.thread_names[0] = make_view("thread-1");
  state.thread_names[1] = make_view("thread-2");
}

static gdbstub_stop_reason make_stop_reason(uint64_t tid) {
  gdbstub_stop_reason reason{};
  reason.kind = GDBSTUB_STOP_SW_BREAK;
  reason.signal = 5;
  reason.addr = 0;
  reason.exit_code = 0;
  reason.has_thread_id = 1;
  reason.thread_id = tid;
  return reason;
}

static size_t reg_size(void* ctx, int regno) {
  (void) ctx;
  (void) regno;
  return k_reg_size;
}

static gdbstub_target_status read_reg(void* ctx, int regno, uint8_t* out, size_t out_len) {
  auto* state = static_cast<capi_state*>(ctx);
  size_t offset = static_cast<size_t>(regno) * k_reg_size;
  if (offset + out_len > sizeof(state->regs)) {
    return GDBSTUB_TARGET_INVALID;
  }
  std::memcpy(out, state->regs + offset, out_len);
  return GDBSTUB_TARGET_OK;
}

static gdbstub_target_status write_reg(void* ctx, int regno, const uint8_t* data, size_t data_len) {
  auto* state = static_cast<capi_state*>(ctx);
  size_t offset = static_cast<size_t>(regno) * k_reg_size;
  if (offset + data_len > sizeof(state->regs)) {
    return GDBSTUB_TARGET_INVALID;
  }
  std::memcpy(state->regs + offset, data, data_len);
  return GDBSTUB_TARGET_OK;
}

static gdbstub_target_status read_mem(void* ctx, uint64_t addr, uint8_t* out, size_t out_len) {
  auto* state = static_cast<capi_state*>(ctx);
  if (addr < k_mem_base) {
    return GDBSTUB_TARGET_FAULT;
  }
  size_t offset = static_cast<size_t>(addr - k_mem_base);
  if (offset >= k_mem_size) {
    return GDBSTUB_TARGET_FAULT;
  }
  size_t count = std::min(out_len, k_mem_size - offset);
  std::memset(out, 0, out_len);
  std::memcpy(out, state->mem + offset, count);
  return GDBSTUB_TARGET_OK;
}

static gdbstub_target_status write_mem(void* ctx, uint64_t addr, const uint8_t* data, size_t data_len) {
  auto* state = static_cast<capi_state*>(ctx);
  if (addr < k_mem_base) {
    return GDBSTUB_TARGET_FAULT;
  }
  size_t offset = static_cast<size_t>(addr - k_mem_base);
  if (offset >= k_mem_size) {
    return GDBSTUB_TARGET_FAULT;
  }
  size_t count = std::min(data_len, k_mem_size - offset);
  std::memcpy(state->mem + offset, data, count);
  return GDBSTUB_TARGET_OK;
}

static gdbstub_resume_result resume(void* ctx, const gdbstub_resume_request* request) {
  (void) request;
  auto* state = static_cast<capi_state*>(ctx);
  gdbstub_resume_result result{};
  if (state->resume_running) {
    state->running = true;
    result.state = GDBSTUB_RESUME_RUNNING;
    return result;
  }
  result.state = GDBSTUB_RESUME_STOPPED;
  result.stop = make_stop_reason(state->current_thread);
  return result;
}

static void interrupt(void* ctx) {
  auto* state = static_cast<capi_state*>(ctx);
  state->running = false;
}

static uint8_t poll_stop(void* ctx, gdbstub_stop_reason* out) {
  auto* state = static_cast<capi_state*>(ctx);
  if (!state->running) {
    return 0;
  }
  state->running = false;
  if (out) {
    *out = make_stop_reason(state->current_thread);
  }
  return 1;
}

static void set_stop_notifier(void* ctx, gdbstub_stop_notifier notifier) {
  auto* state = static_cast<capi_state*>(ctx);
  state->notifier = notifier;
  state->has_notifier = true;
}

static gdbstub_target_status set_breakpoint(void* ctx, const gdbstub_breakpoint_spec* spec) {
  (void) spec;
  auto* state = static_cast<capi_state*>(ctx);
  state->breakpoints_set++;
  return GDBSTUB_TARGET_OK;
}

static gdbstub_target_status remove_breakpoint(void* ctx, const gdbstub_breakpoint_spec* spec) {
  (void) spec;
  auto* state = static_cast<capi_state*>(ctx);
  state->breakpoints_removed++;
  return GDBSTUB_TARGET_OK;
}

static uint8_t region_info(void* ctx, uint64_t addr, gdbstub_memory_region_info* out) {
  auto* state = static_cast<capi_state*>(ctx);
  if (addr < k_mem_base || addr >= k_mem_base + k_mem_size) {
    return 0;
  }
  if (out) {
    *out = state->region_info;
  }
  return 1;
}

static gdbstub_slice_region memory_map(void* ctx) {
  auto* state = static_cast<capi_state*>(ctx);
  gdbstub_slice_region slice{};
  slice.data = &state->region;
  slice.len = 1;
  return slice;
}

static gdbstub_slice_u64 thread_ids(void* ctx) {
  auto* state = static_cast<capi_state*>(ctx);
  gdbstub_slice_u64 slice{};
  slice.data = state->threads;
  slice.len = 2;
  return slice;
}

static uint64_t current_thread(void* ctx) {
  auto* state = static_cast<capi_state*>(ctx);
  return state->current_thread;
}

static gdbstub_target_status set_current_thread(void* ctx, uint64_t tid) {
  auto* state = static_cast<capi_state*>(ctx);
  state->current_thread = tid;
  return GDBSTUB_TARGET_OK;
}

static uint8_t thread_pc(void* ctx, uint64_t tid, uint64_t* out) {
  (void) ctx;
  if (out) {
    *out = 0x1000 + tid;
  }
  return 1;
}

static uint8_t thread_name(void* ctx, uint64_t tid, gdbstub_string_view* out) {
  auto* state = static_cast<capi_state*>(ctx);
  if (!out || tid == 0 || tid > 2) {
    return 0;
  }
  *out = state->thread_names[tid - 1];
  return 1;
}

static uint8_t thread_stop_reason(void* ctx, uint64_t tid, gdbstub_stop_reason* out) {
  (void) ctx;
  if (!out) {
    return 0;
  }
  *out = make_stop_reason(tid);
  return 1;
}

static uint8_t get_host_info(void* ctx, gdbstub_host_info* out) {
  auto* state = static_cast<capi_state*>(ctx);
  if (!out) {
    return 0;
  }
  *out = state->host;
  return 1;
}

static uint8_t get_process_info(void* ctx, gdbstub_process_info* out) {
  auto* state = static_cast<capi_state*>(ctx);
  if (!out) {
    return 0;
  }
  *out = state->process;
  return 1;
}

static uint8_t get_shlib_info(void* ctx, gdbstub_shlib_info* out) {
  auto* state = static_cast<capi_state*>(ctx);
  if (!out) {
    return 0;
  }
  *out = state->shlib;
  return 1;
}

static uint8_t get_register_info(void* ctx, int regno, gdbstub_register_info* out) {
  auto* state = static_cast<capi_state*>(ctx);
  if (!out || regno != 0) {
    return 0;
  }
  *out = state->reg_info;
  return 1;
}

static void setup_config(capi_state& state) {
  state.regs_iface.ctx = &state;
  state.regs_iface.reg_size = &reg_size;
  state.regs_iface.read_reg = &read_reg;
  state.regs_iface.write_reg = &write_reg;

  state.mem_iface.ctx = &state;
  state.mem_iface.read_mem = &read_mem;
  state.mem_iface.write_mem = &write_mem;

  state.run_iface.ctx = &state;
  state.run_iface.resume = &resume;
  state.run_iface.interrupt = &interrupt;
  state.run_iface.poll_stop = state.enable_poll_stop ? &poll_stop : nullptr;
  state.run_iface.set_stop_notifier = state.enable_stop_notifier ? &set_stop_notifier : nullptr;

  state.bp_iface.ctx = &state;
  state.bp_iface.set_breakpoint = &set_breakpoint;
  state.bp_iface.remove_breakpoint = &remove_breakpoint;

  state.layout_iface.ctx = &state;
  state.layout_iface.region_info = &region_info;
  state.layout_iface.memory_map = &memory_map;

  state.threads_iface.ctx = &state;
  state.threads_iface.thread_ids = &thread_ids;
  state.threads_iface.current_thread = &current_thread;
  state.threads_iface.set_current_thread = &set_current_thread;
  state.threads_iface.thread_pc = &thread_pc;
  state.threads_iface.thread_name = &thread_name;
  state.threads_iface.thread_stop_reason = &thread_stop_reason;

  state.host_iface.ctx = &state;
  state.host_iface.get_host_info = &get_host_info;

  state.process_iface.ctx = &state;
  state.process_iface.get_process_info = &get_process_info;

  state.shlib_iface.ctx = &state;
  state.shlib_iface.get_shlib_info = &get_shlib_info;

  state.reg_info_iface.ctx = &state;
  state.reg_info_iface.get_register_info = &get_register_info;

  state.config.regs = state.regs_iface;
  state.config.mem = state.mem_iface;
  state.config.run = state.run_iface;
  state.config.breakpoints = &state.bp_iface;
  state.config.memory_layout = &state.layout_iface;
  state.config.threads = &state.threads_iface;
  state.config.host = &state.host_iface;
  state.config.process = &state.process_iface;
  state.config.shlib = &state.shlib_iface;
  state.config.reg_info = &state.reg_info_iface;
}

static gdbstub_string_view make_view(const std::string& text) {
  gdbstub_string_view view{};
  view.data = text.data();
  view.size = text.size();
  return view;
}

static std::optional<uint16_t> listen_on_available_port(
    gdbstub_server* server, std::string_view host, uint16_t base_port, uint16_t max_attempts
) {
  for (uint16_t offset = 0; offset < max_attempts; ++offset) {
    uint16_t port = static_cast<uint16_t>(base_port + offset);
    std::string address = std::string(host) + ":" + std::to_string(port);
    if (gdbstub_server_listen(server, make_view(address))) {
      return port;
    }
  }
  return std::nullopt;
}

static std::optional<gdbstub::test::client_reply> wait_for_reply(
    gdbstub_server* server, gdbstub::test::tcp_client& client, std::chrono::milliseconds timeout
) {
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    gdbstub_server_poll(server, 10);
    if (auto reply = client.read_packet(std::chrono::milliseconds(10))) {
      return reply;
    }
  }
  return std::nullopt;
}

struct capi_server {
  gdbstub_target* target = nullptr;
  gdbstub_server* server = nullptr;

  ~capi_server() {
    if (server) {
      gdbstub_server_stop(server);
      gdbstub_server_destroy(server);
    }
    if (target) {
      gdbstub_target_destroy(target);
    }
  }
};

static capi_server make_server(capi_state& state) {
  capi_server result{};
  setup_config(state);
  result.target = gdbstub_target_create(&state.config);
  REQUIRE(result.target != nullptr);

  gdbstub_arch_spec arch{};
  arch.target_xml = make_view("<target version=\"1.0\"><architecture>riscv:rv32</architecture></target>");
  arch.xml_arch_name = make_view("riscv");
  arch.osabi = make_view("bare");
  arch.reg_count = k_reg_count;
  arch.pc_reg_num = k_reg_count - 1;

  auto transport = gdbstub_transport_tcp_create();
  REQUIRE(transport != nullptr);

  result.server = gdbstub_server_create(result.target, arch, transport);
  REQUIRE(result.server != nullptr);
  return result;
}

} // namespace

TEST_CASE("capi tcp integration handles core packets") {
  capi_state state;
  init_state(state);
  state.resume_running = false;

  auto server_handle = make_server(state);

  constexpr std::string_view k_host = "127.0.0.1";
  auto port = listen_on_available_port(server_handle.server, k_host, 45000, 200);
  REQUIRE(port.has_value());

  std::atomic<bool> accepted{false};
  std::thread accept_thread([&]() { accepted = gdbstub_server_wait_for_connection(server_handle.server) != 0; });

  gdbstub::test::tcp_client client;
  REQUIRE(client.connect(k_host, *port));
  accept_thread.join();
  REQUIRE(accepted.load());

  REQUIRE(client.send_packet("qSupported"));
  auto supported = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(supported.has_value());
  CHECK(supported->payload.find("PacketSize=") != std::string::npos);
  CHECK(supported->payload.find("qXfer:features:read+") != std::string::npos);
  CHECK(supported->payload.find("xmlRegisters=") != std::string::npos);
  CHECK(supported->payload.find("qHostInfo+") != std::string::npos);
  CHECK(supported->payload.find("qProcessInfo+") != std::string::npos);
  CHECK(supported->payload.find("qMemoryRegionInfo+") != std::string::npos);

  REQUIRE(client.send_packet("qRegisterInfo0"));
  auto reginfo = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(reginfo.has_value());
  CHECK(reginfo->payload.find("name:r0;") != std::string::npos);

  REQUIRE(client.send_packet("P1=01020304"));
  auto write_reg = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(write_reg.has_value());
  CHECK(write_reg->payload == "OK");

  REQUIRE(client.send_packet("p1"));
  auto read_reg = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(read_reg.has_value());
  CHECK(read_reg->payload == "01020304");

  REQUIRE(client.send_packet("M1000,4:01020304"));
  auto write_mem = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(write_mem.has_value());
  CHECK(write_mem->payload == "OK");

  REQUIRE(client.send_packet("m1000,4"));
  auto read_mem = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(read_mem.has_value());
  CHECK(read_mem->payload == "01020304");

  REQUIRE(client.send_packet("qMemoryRegionInfo:1000"));
  auto region = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(region.has_value());
  CHECK(region->payload.find("start:") != std::string::npos);
  CHECK(region->payload.find("permissions:") != std::string::npos);

  REQUIRE(client.send_packet("qXfer:memory-map:read::0,200"));
  auto memmap = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(memmap.has_value());
  CHECK(memmap->payload.find("<memory-map>") != std::string::npos);

  REQUIRE(client.send_packet("qHostInfo"));
  auto host = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(host.has_value());
  CHECK(host->payload.find("triple:") != std::string::npos);

  REQUIRE(client.send_packet("qProcessInfo"));
  auto proc = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(proc.has_value());
  CHECK(proc->payload.find("pid:") != std::string::npos);

  REQUIRE(client.send_packet("qShlibInfoAddr"));
  auto shlib = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(shlib.has_value());
  CHECK(shlib->payload == "11223344");

  REQUIRE(client.send_packet("Z0,1008,4"));
  auto bp = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(bp.has_value());
  CHECK(bp->payload == "OK");
  CHECK(state.breakpoints_set == 1);

  REQUIRE(client.send_packet("z0,1008,4"));
  auto bp_clear = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(bp_clear.has_value());
  CHECK(bp_clear->payload == "OK");
  CHECK(state.breakpoints_removed == 1);

  REQUIRE(client.send_packet("c"));
  auto stop = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(stop.has_value());
  CHECK(stop->payload.rfind("T", 0) == 0);

  REQUIRE(client.send_packet("D"));
  auto detach = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(detach.has_value());
  CHECK(detach->payload == "OK");

  client.close();
}

TEST_CASE("capi async notifier sends stop reply") {
  capi_state state;
  init_state(state);
  state.resume_running = true;
  state.enable_poll_stop = false;

  auto server_handle = make_server(state);

  constexpr std::string_view k_host = "127.0.0.1";
  auto port = listen_on_available_port(server_handle.server, k_host, 45200, 200);
  REQUIRE(port.has_value());

  std::atomic<bool> accepted{false};
  std::thread accept_thread([&]() { accepted = gdbstub_server_wait_for_connection(server_handle.server) != 0; });

  gdbstub::test::tcp_client client;
  REQUIRE(client.connect(k_host, *port));
  accept_thread.join();
  REQUIRE(accepted.load());

  REQUIRE(client.send_packet("c"));
  auto initial = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(50));
  CHECK(!initial.has_value());

  REQUIRE(state.has_notifier);
  auto reason = make_stop_reason(state.current_thread);
  state.notifier.notify(state.notifier.ctx, &reason);

  auto stop = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(stop.has_value());
  CHECK(stop->payload.rfind("T", 0) == 0);

  REQUIRE(client.send_packet("D"));
  auto detach = wait_for_reply(server_handle.server, client, std::chrono::milliseconds(200));
  REQUIRE(detach.has_value());
  CHECK(detach->payload == "OK");

  client.close();
}
