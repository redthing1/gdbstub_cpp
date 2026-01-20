#include "doctest/doctest.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "gdbstub/protocol/rsp_core.hpp"
#include "gdbstub/server/server.hpp"
#include "gdbstub/tcp_test_client.hpp"
#include "gdbstub/transport/transport.hpp"
#include "gdbstub/transport/transport_tcp.hpp"

namespace {

class loopback_transport final : public gdbstub::transport {
public:
  bool listen(std::string_view) override {
    listening_ = true;
    return true;
  }

  bool accept() override {
    if (!listening_) {
      return false;
    }
    connected_ = true;
    return true;
  }

  bool connected() const override { return connected_; }

  bool readable(std::chrono::milliseconds) override { return !incoming_.empty(); }

  std::ptrdiff_t read(std::span<std::byte> out) override {
    if (incoming_.empty()) {
      return 0;
    }
    size_t count = std::min(out.size(), incoming_.size());
    std::memcpy(out.data(), incoming_.data(), count);
    incoming_.erase(incoming_.begin(), incoming_.begin() + static_cast<long>(count));
    return static_cast<std::ptrdiff_t>(count);
  }

  std::ptrdiff_t write(std::span<const std::byte> data) override {
    outgoing_.insert(outgoing_.end(), data.begin(), data.end());
    return static_cast<std::ptrdiff_t>(data.size());
  }

  void disconnect() override { connected_ = false; }

  void close() override {
    connected_ = false;
    listening_ = false;
    incoming_.clear();
    outgoing_.clear();
  }

  void push_incoming(std::string_view data) {
    auto bytes = std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size());
    incoming_.insert(incoming_.end(), bytes.begin(), bytes.end());
  }

  std::string take_outgoing() {
    std::string result(reinterpret_cast<const char*>(outgoing_.data()), outgoing_.size());
    outgoing_.clear();
    return result;
  }

private:
  bool listening_ = false;
  bool connected_ = false;
  std::vector<std::byte> incoming_;
  std::vector<std::byte> outgoing_;
};

struct mock_state {
  std::array<uint32_t, 3> regs{};
  std::vector<std::byte> memory = std::vector<std::byte>(0x2000);
  std::vector<uint64_t> threads = {1};
  std::unordered_map<uint64_t, uint64_t> thread_pcs;
  std::optional<gdbstub::stop_reason> stop_for_threads;
  std::optional<gdbstub::stop_reason> resume_stop;
  std::optional<gdbstub::shlib_info> shlib;
  std::optional<gdbstub::process_launch_request> last_launch;
  std::optional<uint64_t> last_attach_pid;
  std::optional<uint64_t> last_kill_pid;
  bool last_kill_has_pid = false;
  bool restart_called = false;
  std::optional<gdbstub::resume_result> launch_result;
  std::optional<gdbstub::resume_result> attach_result;
  std::optional<gdbstub::resume_result> restart_result;
  std::optional<gdbstub::offsets_info> offsets;
  std::optional<gdbstub::resume_request> last_resume;
  std::optional<uint64_t> last_set_thread;
  std::optional<gdbstub::breakpoint_request> last_breakpoint;
  std::optional<gdbstub::breakpoint_request> last_removed_breakpoint;
  std::vector<gdbstub::library_entry> libraries;
  std::optional<uint64_t> libraries_generation;
  std::vector<gdbstub::lldb::process_kv_pair> lldb_process_extras;
  std::optional<std::string> lldb_loaded_libraries_json;
  std::optional<gdbstub::lldb::loaded_libraries_request> last_loaded_libraries_request;
  gdbstub::target_status breakpoint_status = gdbstub::target_status::ok;
  gdbstub::target_status resume_status = gdbstub::target_status::ok;
  gdbstub::target_status kill_status = gdbstub::target_status::ok;
  gdbstub::run_capabilities run_caps{};
  gdbstub::breakpoint_capabilities breakpoint_caps{};
  bool interrupt_called = false;
  uint64_t current_tid = 1;

  enum class resume_behavior { stop_immediately, run };

  resume_behavior resume_behavior = resume_behavior::stop_immediately;

  mock_state() {
    regs[2] = 0x1000;
    breakpoint_caps.software = true;
  }
};

struct mock_regs {
  mock_state& state;

  size_t reg_size(int) const { return 4; }

  gdbstub::target_status read_reg(int regno, std::span<std::byte> out) {
    if (regno < 0 || regno >= static_cast<int>(state.regs.size()) || out.size() != 4) {
      return gdbstub::target_status::invalid;
    }
    uint32_t value = state.regs[static_cast<size_t>(regno)];
    out[0] = std::byte(value & 0xff);
    out[1] = std::byte((value >> 8) & 0xff);
    out[2] = std::byte((value >> 16) & 0xff);
    out[3] = std::byte((value >> 24) & 0xff);
    return gdbstub::target_status::ok;
  }

  gdbstub::target_status write_reg(int regno, std::span<const std::byte> data) {
    if (regno < 0 || regno >= static_cast<int>(state.regs.size()) || data.size() != 4) {
      return gdbstub::target_status::invalid;
    }
    uint32_t value = static_cast<uint32_t>(data[0]) |
                     (static_cast<uint32_t>(data[1]) << 8) |
                     (static_cast<uint32_t>(data[2]) << 16) |
                     (static_cast<uint32_t>(data[3]) << 24);
    state.regs[static_cast<size_t>(regno)] = value;
    return gdbstub::target_status::ok;
  }
};

struct mock_mem {
  mock_state& state;

  gdbstub::target_status read_mem(uint64_t addr, std::span<std::byte> out) {
    if (addr + out.size() > state.memory.size()) {
      return gdbstub::target_status::fault;
    }
    std::memcpy(out.data(), state.memory.data() + addr, out.size());
    return gdbstub::target_status::ok;
  }

  gdbstub::target_status write_mem(uint64_t addr, std::span<const std::byte> data) {
    if (addr + data.size() > state.memory.size()) {
      return gdbstub::target_status::fault;
    }
    std::memcpy(state.memory.data() + addr, data.data(), data.size());
    return gdbstub::target_status::ok;
  }
};

struct mock_run {
  mock_state& state;

  gdbstub::resume_result resume(const gdbstub::resume_request& request) {
    state.last_resume = request;
    if (request.action == gdbstub::resume_action::step) {
      state.regs[2] += 4;
    }

    gdbstub::resume_result result;
    result.status = state.resume_status;
    if (result.status != gdbstub::target_status::ok) {
      return result;
    }
    if (state.resume_behavior == mock_state::resume_behavior::run) {
      result.state = gdbstub::resume_result::state::running;
      return result;
    }

    result.state = gdbstub::resume_result::state::stopped;
    if (state.resume_stop) {
      result.stop = *state.resume_stop;
    } else {
      result.stop = {gdbstub::stop_kind::signal, 5, 0, 0, 1};
    }
    return result;
  }

  void interrupt() { state.interrupt_called = true; }

  std::optional<gdbstub::stop_reason> poll_stop() { return std::nullopt; }

  gdbstub::run_capabilities capabilities() const { return state.run_caps; }
};

struct mock_breakpoints {
  mock_state& state;

  gdbstub::target_status set_breakpoint(const gdbstub::breakpoint_request& request) {
    state.last_breakpoint = request;
    return state.breakpoint_status;
  }

  gdbstub::target_status remove_breakpoint(const gdbstub::breakpoint_request& request) {
    state.last_removed_breakpoint = request;
    return state.breakpoint_status;
  }

  gdbstub::breakpoint_capabilities capabilities() const { return state.breakpoint_caps; }
};

struct mock_memory_layout {
  std::optional<gdbstub::memory_region_info> region_info(uint64_t addr) {
    auto regions = memory_map();
    return gdbstub::region_info_from_map(regions, addr);
  }

  std::vector<gdbstub::memory_region> memory_map() {
    gdbstub::memory_region region{
        0x1000,
        0x100,
        gdbstub::mem_perm::read | gdbstub::mem_perm::write | gdbstub::mem_perm::exec
    };
    region.name = "test";
    region.types = {"stack"};
    return {std::move(region)};
  }
};

struct mock_threads {
  mock_state& state;

  std::vector<uint64_t> thread_ids() { return state.threads; }
  uint64_t current_thread() const { return state.current_tid; }
  gdbstub::target_status set_current_thread(uint64_t tid) {
    state.current_tid = tid;
    state.last_set_thread = tid;
    return gdbstub::target_status::ok;
  }
  std::optional<uint64_t> thread_pc(uint64_t tid) {
    if (!state.thread_pcs.empty()) {
      auto it = state.thread_pcs.find(tid);
      if (it != state.thread_pcs.end()) {
        return it->second;
      }
      return std::nullopt;
    }
    return state.regs[2];
  }
  std::optional<std::string> thread_name(uint64_t) { return std::nullopt; }
  std::optional<gdbstub::stop_reason> thread_stop_reason(uint64_t) { return state.stop_for_threads; }
};

struct mock_host {
  std::optional<gdbstub::host_info> get_host_info() {
    return gdbstub::host_info{
        "riscv32-unknown-elf", "little", 4, "mock-host", "1.0", "build", "kernel", std::nullopt, std::nullopt,
        std::nullopt};
  }
};

struct mock_process {
  mock_state& state;

  explicit mock_process(mock_state& state_in) : state(state_in) {}

  std::optional<gdbstub::process_info> get_process_info() {
    gdbstub::process_info info{42, "riscv32-unknown-elf", "little", 4, "bare"};
    return info;
  }
};

struct mock_shlib {
  mock_state& state;

  std::optional<gdbstub::shlib_info> get_shlib_info() { return state.shlib; }
};

struct mock_libraries {
  mock_state& state;

  std::vector<gdbstub::library_entry> libraries() const { return state.libraries; }
  std::optional<uint64_t> libraries_generation() const { return state.libraries_generation; }
};

struct mock_lldb {
  mock_state& state;

  std::optional<std::vector<gdbstub::lldb::process_kv_pair>> process_info_extras() const {
    return state.lldb_process_extras;
  }

  std::optional<std::string> loaded_libraries_json(
      const gdbstub::lldb::loaded_libraries_request& request
  ) {
    state.last_loaded_libraries_request = request;
    return state.lldb_loaded_libraries_json;
  }
};

struct mock_process_control {
  mock_state& state;

  std::optional<gdbstub::resume_result> launch(const gdbstub::process_launch_request& request) {
    state.last_launch = request;
    return state.launch_result;
  }

  std::optional<gdbstub::resume_result> attach(uint64_t pid) {
    state.last_attach_pid = pid;
    return state.attach_result;
  }

  gdbstub::target_status kill(std::optional<uint64_t> pid) {
    state.last_kill_has_pid = pid.has_value();
    state.last_kill_pid = pid.value_or(0);
    return state.kill_status;
  }

  std::optional<gdbstub::resume_result> restart() {
    state.restart_called = true;
    return state.restart_result;
  }
};

struct mock_offsets {
  mock_state& state;

  std::optional<gdbstub::offsets_info> get_offsets_info() { return state.offsets; }
};

struct mock_register_info {
  std::optional<gdbstub::register_info> get_register_info(int regno) {
    if (regno < 0 || regno >= 3) {
      return std::nullopt;
    }
    gdbstub::register_info info;
    if (regno == 2) {
      info.name = "pc";
      info.generic = "pc";
    } else {
      info.name = "r" + std::to_string(regno);
    }
    info.bitsize = 32;
    info.encoding = "uint";
    info.format = "hex";
    info.set = "general";
    return info;
  }
};

struct mock_components {
  mock_state& state;
  mock_regs regs{state};
  mock_mem mem{state};
  mock_run run{state};
  mock_breakpoints breakpoints{state};
  mock_memory_layout memory_layout{};
  mock_threads threads{state};
  mock_host host{};
  mock_process process{state};
  mock_shlib shlib{state};
  mock_libraries libraries{state};
  mock_lldb lldb{state};
  mock_process_control process_control{state};
  mock_offsets offsets{state};
  mock_register_info reg_info{};
};

struct parsed_output {
  std::vector<gdbstub::rsp::input_event> packets;
  std::vector<gdbstub::rsp::input_event> notifications;
  size_t ack_count = 0;
  size_t nack_count = 0;
};

std::span<const std::byte> as_bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

parsed_output parse_output(std::string_view data) {
  gdbstub::rsp::stream_parser parser;
  parser.append(as_bytes(data));

  parsed_output out;
  while (parser.has_event()) {
    auto event = parser.pop_event();
    if (event.kind == gdbstub::rsp::event_kind::ack) {
      ++out.ack_count;
    } else if (event.kind == gdbstub::rsp::event_kind::nack) {
      ++out.nack_count;
    } else if (event.kind == gdbstub::rsp::event_kind::notification) {
      out.notifications.push_back(std::move(event));
    } else if (event.kind == gdbstub::rsp::event_kind::packet) {
      out.packets.push_back(std::move(event));
    }
  }
  return out;
}

gdbstub::target make_target(mock_components& target) {
  return gdbstub::make_target(
      target.regs,
      target.mem,
      target.run,
      target.breakpoints,
      target.threads,
      target.memory_layout,
      target.host,
      target.process,
      target.shlib,
      target.libraries,
      target.lldb,
      target.process_control,
      target.offsets,
      target.reg_info
  );
}

gdbstub::target make_target_without_lldb(mock_components& target) {
  return gdbstub::make_target(
      target.regs,
      target.mem,
      target.run,
      target.breakpoints,
      target.threads,
      target.memory_layout,
      target.host,
      target.process,
      target.shlib,
      target.libraries,
      target.process_control,
      target.offsets,
      target.reg_info
  );
}

std::string unescape_payload(std::string payload) {
  gdbstub::rsp::unescape_binary(payload);
  return payload;
}

parsed_output send_packet(
    gdbstub::server& server,
    loopback_transport& transport,
    std::string_view payload
) {
  auto packet = gdbstub::rsp::build_packet(payload);
  transport.push_incoming(packet);
  server.poll(std::chrono::milliseconds(0));
  return parse_output(transport.take_outgoing());
}

} // namespace

TEST_CASE("server responds to qSupported") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;
  arch.target_xml = "<target></target>";
  arch.xml_arch_name = "org.gnu.gdb.riscv.cpu";

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto output = send_packet(server, *transport_ptr, "qSupported");
  REQUIRE(output.ack_count == 1);
  REQUIRE(output.packets.size() == 1);
  auto payload = output.packets[0].payload;
  CHECK(payload.find("PacketSize=") != std::string::npos);
  CHECK(payload.find("vContSupported+") != std::string::npos);
  CHECK(payload.find("QStartNoAckMode+") != std::string::npos);
  CHECK(payload.find("qXfer:features:read+") != std::string::npos);
  CHECK(payload.find("swbreak+") != std::string::npos);
  CHECK(payload.find("qMemoryRegionInfo+") != std::string::npos);
  CHECK(payload.find("qXfer:memory-map:read+") != std::string::npos);
  CHECK(payload.find("qXfer:libraries:read+") != std::string::npos);
  CHECK(payload.find("ConditionalBreakpoints+") == std::string::npos);
  CHECK(payload.find("BreakpointCommands+") == std::string::npos);
}

TEST_CASE("server advertises optional capabilities in qSupported") {
  mock_state state;
  state.run_caps.reverse_continue = true;
  state.run_caps.reverse_step = true;
  state.run_caps.range_step = true;
  state.run_caps.non_stop = true;
  state.breakpoint_caps.software = true;
  state.breakpoint_caps.hardware = true;
  state.breakpoint_caps.supports_conditional = true;
  state.breakpoint_caps.supports_commands = true;

  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto output = send_packet(server, *transport_ptr, "qSupported");
  REQUIRE(output.packets.size() == 1);
  auto payload = output.packets[0].payload;
  CHECK(payload.find("ReverseContinue+") != std::string::npos);
  CHECK(payload.find("ReverseStep+") != std::string::npos);
  CHECK(payload.find("QNonStop+") != std::string::npos);
  CHECK(payload.find("hwbreak+") != std::string::npos);
  CHECK(payload.find("ConditionalBreakpoints+") != std::string::npos);
  CHECK(payload.find("BreakpointCommands+") != std::string::npos);
}

TEST_CASE("server responds to qRegisterInfo") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto output = send_packet(server, *transport_ptr, "qRegisterInfo0");
  REQUIRE(output.packets.size() == 1);
  CHECK(output.packets[0].payload.find("name:r0;") != std::string::npos);
  CHECK(output.packets[0].payload.find("bitsize:32;") != std::string::npos);
  CHECK(output.packets[0].payload.find("offset:0;") != std::string::npos);

  output = send_packet(server, *transport_ptr, "qRegisterInfo1");
  REQUIRE(output.packets.size() == 1);
  CHECK(output.packets[0].payload.find("name:r1;") != std::string::npos);
  CHECK(output.packets[0].payload.find("offset:4;") != std::string::npos);

  output = send_packet(server, *transport_ptr, "qRegisterInfo2");
  REQUIRE(output.packets.size() == 1);
  CHECK(output.packets[0].payload.find("name:pc;") != std::string::npos);
  CHECK(output.packets[0].payload.find("generic:pc;") != std::string::npos);
  CHECK(output.packets[0].payload.find("offset:8;") != std::string::npos);

  output = send_packet(server, *transport_ptr, "qRegisterInfo3");
  REQUIRE(output.packets.size() == 1);
  CHECK(output.packets[0].payload == "E45");
}

TEST_CASE("server reports gdbserver version") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto output = send_packet(server, *transport_ptr, "qGDBServerVersion");
  REQUIRE(output.packets.size() == 1);
  CHECK(output.packets[0].payload.find("name:gdbstub_cpp") != std::string::npos);
  CHECK(output.packets[0].payload.find("version:") != std::string::npos);
}

TEST_CASE("server responds to qThreadStopInfo") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto output = send_packet(server, *transport_ptr, "qThreadStopInfo1");
  REQUIRE(output.packets.size() == 1);
  CHECK(output.packets[0].payload.rfind("T05", 0) == 0);
  CHECK(output.packets[0].payload.find("thread:1;") != std::string::npos);
}

TEST_CASE("server reads and writes registers") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto write_out = send_packet(server, *transport_ptr, "P1=78563412");
  REQUIRE(write_out.packets.size() == 1);
  CHECK(write_out.packets[0].payload == "OK");

  auto read_out = send_packet(server, *transport_ptr, "p1");
  REQUIRE(read_out.packets.size() == 1);
  CHECK(read_out.packets[0].payload == "78563412");
}

TEST_CASE("server reads and writes all registers") {
  mock_state state;
  mock_components target(state);
  state.regs = {0x11223344, 0x55667788, 0x99aabbcc};

  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto read_out = send_packet(server, *transport_ptr, "g");
  REQUIRE(read_out.packets.size() == 1);
  CHECK(read_out.packets[0].payload == "4433221188776655ccbbaa99");

  auto write_out = send_packet(server, *transport_ptr, "G0102030405060708090a0b0c");
  REQUIRE(write_out.packets.size() == 1);
  CHECK(write_out.packets[0].payload == "OK");
  CHECK(state.regs[0] == 0x04030201);
  CHECK(state.regs[1] == 0x08070605);
  CHECK(state.regs[2] == 0x0c0b0a09);
}

TEST_CASE("server rejects malformed G packets") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "G00");
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "E16");
}

TEST_CASE("server reads memory") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  state.memory[0x1000] = std::byte{0xaa};
  state.memory[0x1001] = std::byte{0xbb};
  state.memory[0x1002] = std::byte{0xcc};
  state.memory[0x1003] = std::byte{0xdd};

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "m1000,4");
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "aabbccdd");
}

TEST_CASE("server writes memory in hex and binary forms") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto hex_out = send_packet(server, *transport_ptr, "M1000,4:01020304");
  REQUIRE(hex_out.packets.size() == 1);
  CHECK(hex_out.packets[0].payload == "OK");
  CHECK(state.memory[0x1000] == std::byte{0x01});
  CHECK(state.memory[0x1001] == std::byte{0x02});
  CHECK(state.memory[0x1002] == std::byte{0x03});
  CHECK(state.memory[0x1003] == std::byte{0x04});

  std::string data = "A$#}";
  std::string payload = "X1000,4:";
  payload += gdbstub::rsp::escape_binary(as_bytes(data));
  auto bin_out = send_packet(server, *transport_ptr, payload);
  REQUIRE(bin_out.packets.size() == 1);
  CHECK(bin_out.packets[0].payload == "OK");
  CHECK(state.memory[0x1000] == std::byte{'A'});
  CHECK(state.memory[0x1001] == std::byte{'$'});
  CHECK(state.memory[0x1002] == std::byte{'#'});
  CHECK(state.memory[0x1003] == std::byte{'}'});
}

TEST_CASE("server reports memory faults") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "m1fff,2");
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "E0e");
}

TEST_CASE("server handles no-ack mode") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto start_noack = send_packet(server, *transport_ptr, "QStartNoAckMode");
  REQUIRE(start_noack.ack_count == 1);
  REQUIRE(start_noack.packets.size() == 1);
  CHECK(start_noack.packets[0].payload == "OK");

  auto host_info = send_packet(server, *transport_ptr, "qHostInfo");
  CHECK(host_info.ack_count == 0);
  REQUIRE(host_info.packets.size() == 1);
  CHECK(host_info.packets[0].payload.find("triple:") != std::string::npos);
  CHECK(host_info.packets[0].payload.find("os_version:1.0;") != std::string::npos);
}

TEST_CASE("server appends LLDB process info extras when provided") {
  mock_state state;
  state.lldb_process_extras = {
      {"ext-raw", "alpha", 0, gdbstub::lldb::kv_encoding::raw},
      {"ext-hex", "", 0x1234, gdbstub::lldb::kv_encoding::hex_u64},
      {"ext-dec", "", 42, gdbstub::lldb::kv_encoding::dec_u64},
  };
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto proc_info = send_packet(server, *transport_ptr, "qProcessInfo");
  REQUIRE(proc_info.packets.size() == 1);
  const auto& payload = proc_info.packets[0].payload;
  CHECK(payload.find("ext-raw:alpha;") != std::string::npos);
  CHECK(payload.find("ext-hex:1234;") != std::string::npos);
  CHECK(payload.find("ext-dec:42;") != std::string::npos);
}

TEST_CASE("server omits LLDB process info extras without extension") {
  mock_state state;
  state.lldb_process_extras = {
      {"ext-raw", "alpha", 0, gdbstub::lldb::kv_encoding::raw},
      {"ext-hex", "", 0x1234, gdbstub::lldb::kv_encoding::hex_u64},
      {"ext-dec", "", 42, gdbstub::lldb::kv_encoding::dec_u64},
  };
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target_without_lldb(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto proc_info = send_packet(server, *transport_ptr, "qProcessInfo");
  REQUIRE(proc_info.packets.size() == 1);
  const auto& payload = proc_info.packets[0].payload;
  CHECK(payload.find("ext-raw:") == std::string::npos);
  CHECK(payload.find("ext-hex:") == std::string::npos);
  CHECK(payload.find("ext-dec:") == std::string::npos);
}

TEST_CASE("server supports thread suffix on register packets") {
  mock_state state;
  mock_components target(state);
  state.threads = {1, 2};
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "QThreadSuffixSupported");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto read = send_packet(server, *transport_ptr, "p0;thread:2;");
  REQUIRE(read.packets.size() == 1);
  CHECK(state.last_set_thread.has_value());
  CHECK(state.last_set_thread.value() == 2);
}

TEST_CASE("server serves target xml via qXfer") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;
  arch.target_xml = "<target>abc</target>";
  arch.xml_arch_name = "org.gnu.gdb.riscv.cpu";

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qXfer:features:read:target.xml:0,10");
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload[0] == 'm');

  // compatibility for a weird packet i see sometimes
  auto out_empty = send_packet(server, *transport_ptr, "qXfer:features:read::0,10");
  REQUIRE(out_empty.packets.size() == 1);
  CHECK(out_empty.packets[0].payload[0] == 'm');
}

TEST_CASE("server serves library list via qXfer") {
  mock_state state;
  state.libraries.push_back(gdbstub::library_entry::segment("/lib/libc.so.6", {0x1000}));
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qXfer:libraries:read::0,200");
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload[0] == 'l');
  CHECK(out.packets[0].payload.find("<library-list") != std::string::npos);
  CHECK(out.packets[0].payload.find("/lib/libc.so.6") != std::string::npos);
}

TEST_CASE("server sets breakpoints and continues") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto bp = send_packet(server, *transport_ptr, "Z0,1000,4");
  REQUIRE(bp.packets.size() == 1);
  CHECK(bp.packets[0].payload == "OK");
  REQUIRE(state.last_breakpoint.has_value());
  CHECK(state.last_breakpoint->spec.type == gdbstub::breakpoint_type::software);
  CHECK(state.last_breakpoint->spec.addr == 0x1000);
  CHECK(state.last_breakpoint->spec.length == 4);

  auto cont = send_packet(server, *transport_ptr, "c");
  REQUIRE(cont.packets.size() == 1);
  CHECK(cont.packets[0].payload.rfind("T", 0) == 0);
}

TEST_CASE("server accepts breakpoint thread suffix without thread-scoped support") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto bp = send_packet(server, *transport_ptr, "Z0,1000,4;thread:2");
  REQUIRE(bp.packets.size() == 1);
  CHECK(bp.packets[0].payload == "OK");
  REQUIRE(state.last_breakpoint.has_value());
  CHECK(state.last_breakpoint->spec.addr == 0x1000);
  CHECK_FALSE(state.last_breakpoint->thread_id.has_value());
  CHECK_FALSE(state.last_set_thread.has_value());
}

TEST_CASE("server applies breakpoint thread suffix when supported") {
  mock_state state;
  state.breakpoint_caps.supports_thread_suffix = true;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto bp = send_packet(server, *transport_ptr, "Z0,1000,4;thread:2");
  REQUIRE(bp.packets.size() == 1);
  CHECK(bp.packets[0].payload == "OK");
  REQUIRE(state.last_breakpoint.has_value());
  REQUIRE(state.last_breakpoint->thread_id.has_value());
  CHECK(state.last_breakpoint->thread_id.value() == 2);
  REQUIRE(state.last_set_thread.has_value());
  CHECK(state.last_set_thread.value() == 2);
}

TEST_CASE("server rejects conditional breakpoints when unsupported") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto bp = send_packet(server, *transport_ptr, "Z0,1000,4;X1,00");
  REQUIRE(bp.packets.size() == 1);
  CHECK(bp.packets[0].payload.empty());
  CHECK_FALSE(state.last_breakpoint.has_value());
}

TEST_CASE("server forwards conditional breakpoints and commands when supported") {
  mock_state state;
  state.breakpoint_caps.supports_conditional = true;
  state.breakpoint_caps.supports_commands = true;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto bp = send_packet(server, *transport_ptr, "Z0,1000,4;X1,01;cmds:1,X1,02");
  REQUIRE(bp.packets.size() == 1);
  CHECK(bp.packets[0].payload == "OK");
  REQUIRE(state.last_breakpoint.has_value());
  CHECK(state.last_breakpoint->spec.type == gdbstub::breakpoint_type::software);
  CHECK(state.last_breakpoint->spec.addr == 0x1000);
  CHECK(state.last_breakpoint->spec.length == 4);
  REQUIRE(state.last_breakpoint->conditions.size() == 1);
  REQUIRE(state.last_breakpoint->conditions[0].bytes.size() == 1);
  CHECK(state.last_breakpoint->conditions[0].bytes[0] == std::byte{0x01});
  REQUIRE(state.last_breakpoint->commands.has_value());
  CHECK(state.last_breakpoint->commands->persist);
  REQUIRE(state.last_breakpoint->commands->commands.size() == 1);
  REQUIRE(state.last_breakpoint->commands->commands[0].bytes.size() == 1);
  CHECK(state.last_breakpoint->commands->commands[0].bytes[0] == std::byte{0x02});
}

TEST_CASE("server includes hwbreak stop reason when enabled") {
  mock_state state;
  state.breakpoint_caps.hardware = true;
  state.breakpoint_caps.software = true;
  state.resume_stop = gdbstub::stop_reason{gdbstub::stop_kind::hw_break, 5, 0x2000, 0, 1};
  mock_components target(state);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto supported = send_packet(server, *transport_ptr, "qSupported");
  REQUIRE(supported.packets.size() == 1);

  auto cont = send_packet(server, *transport_ptr, "c");
  REQUIRE(cont.packets.size() == 1);
  CHECK(cont.packets[0].payload.find("hwbreak:;") != std::string::npos);
}

TEST_CASE("server parses vCont actions and signals") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto cont = send_packet(server, *transport_ptr, "vCont;c");
  REQUIRE(cont.packets.size() == 1);
  REQUIRE(state.last_resume.has_value());
  CHECK(state.last_resume->action == gdbstub::resume_action::cont);
  CHECK_FALSE(state.last_resume->signal.has_value());

  auto step = send_packet(server, *transport_ptr, "vCont;S0a");
  REQUIRE(step.packets.size() == 1);
  REQUIRE(state.last_resume.has_value());
  CHECK(state.last_resume->action == gdbstub::resume_action::step);
  REQUIRE(state.last_resume->signal.has_value());
  CHECK(state.last_resume->signal.value() == 0x0a);
}

TEST_CASE("server parses reverse continue and step") {
  mock_state state;
  state.run_caps.reverse_continue = true;
  state.run_caps.reverse_step = true;
  mock_components target(state);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out_cont = send_packet(server, *transport_ptr, "bc");
  REQUIRE(out_cont.packets.size() == 1);
  REQUIRE(state.last_resume.has_value());
  CHECK(state.last_resume->action == gdbstub::resume_action::cont);
  CHECK(state.last_resume->direction == gdbstub::resume_direction::reverse);

  auto out_step = send_packet(server, *transport_ptr, "bs");
  REQUIRE(out_step.packets.size() == 1);
  REQUIRE(state.last_resume.has_value());
  CHECK(state.last_resume->action == gdbstub::resume_action::step);
  CHECK(state.last_resume->direction == gdbstub::resume_direction::reverse);
}

TEST_CASE("server parses vCont range stepping") {
  mock_state state;
  state.run_caps.range_step = true;
  mock_components target(state);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto probe = send_packet(server, *transport_ptr, "vCont?");
  REQUIRE(probe.packets.size() == 1);
  CHECK(probe.packets[0].payload.find(";r") != std::string::npos);

  auto out = send_packet(server, *transport_ptr, "vCont;r1000,1010");
  REQUIRE(out.packets.size() == 1);
  REQUIRE(state.last_resume.has_value());
  CHECK(state.last_resume->action == gdbstub::resume_action::range_step);
  REQUIRE(state.last_resume->range.has_value());
  CHECK(state.last_resume->range->start == 0x1000);
  CHECK(state.last_resume->range->end == 0x1010);
}

TEST_CASE("server handles continue with signal and address") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "C05;1234");
  REQUIRE(out.packets.size() == 1);
  REQUIRE(state.last_resume.has_value());
  CHECK(state.last_resume->action == gdbstub::resume_action::cont);
  REQUIRE(state.last_resume->signal.has_value());
  CHECK(state.last_resume->signal.value() == 0x05);
  REQUIRE(state.last_resume->addr.has_value());
  CHECK(state.last_resume->addr.value() == 0x1234);
}

TEST_CASE("server includes thread list in stop reply when enabled") {
  mock_state state;
  mock_components target(state);
  state.threads = {1, 2};
  state.thread_pcs = {{1, 0x1111}, {2, 0x2222}};

  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "QListThreadsInStopReply");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto stop = send_packet(server, *transport_ptr, "c");
  REQUIRE(stop.packets.size() == 1);
  auto payload = stop.packets[0].payload;
  CHECK(payload.find("thread:1;") != std::string::npos);
  CHECK(payload.find("threads:1,2;") != std::string::npos);
  CHECK(payload.find("thread-pcs:1111,2222;") != std::string::npos);
  CHECK(payload.find("2:") != std::string::npos);
}

TEST_CASE("server includes library stop key only when generation changes") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  state.libraries_generation.reset();
  auto first = send_packet(server, *transport_ptr, "c");
  REQUIRE(first.packets.size() == 1);
  CHECK(first.packets[0].payload.find("library:;") == std::string::npos);

  state.libraries_generation = 1;
  auto second = send_packet(server, *transport_ptr, "c");
  REQUIRE(second.packets.size() == 1);
  CHECK(second.packets[0].payload.find("library:;") != std::string::npos);

  auto third = send_packet(server, *transport_ptr, "c");
  REQUIRE(third.packets.size() == 1);
  CHECK(third.packets[0].payload.find("library:;") == std::string::npos);

  state.libraries_generation = 2;
  auto fourth = send_packet(server, *transport_ptr, "c");
  REQUIRE(fourth.packets.size() == 1);
  CHECK(fourth.packets[0].payload.find("library:;") != std::string::npos);
}

TEST_CASE("server reports unsupported watchpoints") {
  mock_state state;
  mock_components target(state);
  state.breakpoint_status = gdbstub::target_status::unsupported;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "Z2,1000,4");
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload.empty());
  REQUIRE(state.last_breakpoint.has_value());
  CHECK(state.last_breakpoint->spec.type == gdbstub::breakpoint_type::watch_write);
}

TEST_CASE("server sends non-stop notifications and drains vStopped") {
  mock_state state;
  state.run_caps.non_stop = true;
  state.resume_behavior = mock_state::resume_behavior::run;
  mock_components target(state);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "QNonStop:1");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto resume = send_packet(server, *transport_ptr, "c");
  REQUIRE(resume.packets.size() == 1);
  CHECK(resume.packets[0].payload == "OK");

  gdbstub::stop_reason stop1{gdbstub::stop_kind::signal, 5, 0x1111, 0, 1};
  gdbstub::stop_reason stop2{gdbstub::stop_kind::signal, 5, 0x2222, 0, 1};
  server.notify_stop(stop1);
  server.notify_stop(stop2);
  server.poll(std::chrono::milliseconds(0));

  auto notify = parse_output(transport_ptr->take_outgoing());
  REQUIRE(notify.notifications.size() == 1);
  CHECK(notify.notifications[0].payload.rfind("Stop:T", 0) == 0);

  auto first = send_packet(server, *transport_ptr, "vStopped");
  REQUIRE(first.packets.size() == 1);
  CHECK(first.packets[0].payload.rfind("T", 0) == 0);

  auto second = send_packet(server, *transport_ptr, "vStopped");
  REQUIRE(second.packets.size() == 1);
  CHECK(second.packets[0].payload == "OK");

  gdbstub::stop_reason stop3{gdbstub::stop_kind::signal, 5, 0x3333, 0, 1};
  server.notify_stop(stop3);
  server.poll(std::chrono::milliseconds(0));

  auto notify_again = parse_output(transport_ptr->take_outgoing());
  REQUIRE(notify_again.notifications.size() == 1);
  CHECK(notify_again.notifications[0].payload.rfind("Stop:T", 0) == 0);
}

TEST_CASE("server includes library key in non-stop notifications on generation change") {
  mock_state state;
  state.run_caps.non_stop = true;
  state.resume_behavior = mock_state::resume_behavior::run;
  state.libraries_generation = 1;
  mock_components target(state);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "QNonStop:1");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto resume = send_packet(server, *transport_ptr, "c");
  REQUIRE(resume.packets.size() == 1);
  CHECK(resume.packets[0].payload == "OK");

  gdbstub::stop_reason stop{gdbstub::stop_kind::signal, 5, 0x1111, 0, 1};
  server.notify_stop(stop);
  server.poll(std::chrono::milliseconds(0));

  auto notify = parse_output(transport_ptr->take_outgoing());
  REQUIRE(notify.notifications.size() == 1);
  CHECK(notify.notifications[0].payload.find("library:;") != std::string::npos);
}

TEST_CASE("server includes replaylog end in stop reply") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  gdbstub::stop_reason reason{gdbstub::stop_kind::signal, 5, 0x0, 0, 1};
  reason.replay_log = gdbstub::replay_log_boundary::end;
  state.resume_stop = reason;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto stop = send_packet(server, *transport_ptr, "c");
  REQUIRE(stop.packets.size() == 1);
  CHECK(stop.packets[0].payload.find("replaylog:end;") != std::string::npos);
}

TEST_CASE("tcp polling integration serves packets") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;
  arch.target_xml = "<target></target>";
  arch.xml_arch_name = "org.gnu.gdb.riscv.cpu";

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  constexpr std::string_view k_host = "127.0.0.1";
  auto port = gdbstub::test::listen_on_available_port(server, k_host, 43000, 200);
  REQUIRE(port.has_value());

  std::atomic<bool> accepted{false};
  std::thread accept_thread([&]() { accepted = server.wait_for_connection(); });

  gdbstub::test::tcp_client client;
  REQUIRE(client.connect(k_host, *port));
  accept_thread.join();
  REQUIRE(accepted.load());

  REQUIRE(client.send_packet("qSupported"));
  auto supported = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(200));
  REQUIRE(supported.has_value());
  CHECK(supported->checksum_ok);
  CHECK(supported->payload.find("PacketSize=") != std::string::npos);

  REQUIRE(client.send_packet("p1"));
  auto reg = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(200));
  REQUIRE(reg.has_value());
  CHECK(reg->checksum_ok);
  CHECK(reg->payload == "00000000");

  client.close();
  server.stop();
}

TEST_CASE("tcp blocking integration uses serve_forever") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  constexpr std::string_view k_host = "127.0.0.1";
  auto port = gdbstub::test::listen_on_available_port(server, k_host, 43200, 200);
  REQUIRE(port.has_value());

  std::thread server_thread([&]() { server.serve_forever(); });

  gdbstub::test::tcp_client client;
  REQUIRE(client.connect(k_host, *port));

  REQUIRE(client.send_packet("qSupported"));
  auto supported = client.read_packet(std::chrono::milliseconds(200));
  REQUIRE(supported.has_value());
  CHECK(supported->checksum_ok);
  CHECK(supported->payload.find("PacketSize=") != std::string::npos);

  client.close();
  server.stop();
  server_thread.join();
}

TEST_CASE("tcp async integration sends stop reply") {
  mock_state state;
  mock_components target(state);
  state.resume_behavior = mock_state::resume_behavior::run;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  constexpr std::string_view k_host = "127.0.0.1";
  auto port = gdbstub::test::listen_on_available_port(server, k_host, 43400, 200);
  REQUIRE(port.has_value());

  std::atomic<bool> accepted{false};
  std::thread accept_thread([&]() { accepted = server.wait_for_connection(); });

  std::atomic<bool> polling{true};
  std::thread poll_thread([&]() {
    while (polling.load()) {
      server.poll(std::chrono::milliseconds(10));
    }
  });

  gdbstub::test::tcp_client client;
  REQUIRE(client.connect(k_host, *port));
  accept_thread.join();
  REQUIRE(accepted.load());

  REQUIRE(client.send_packet("c"));
  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  gdbstub::stop_reason reason;
  reason.kind = gdbstub::stop_kind::sw_break;
  reason.signal = 5;
  reason.thread_id = 1;
  server.notify_stop(reason);

  auto stop = client.read_packet(std::chrono::milliseconds(300));
  REQUIRE(stop.has_value());
  CHECK(stop->checksum_ok);
  CHECK(stop->payload.rfind("T05", 0) == 0);
  CHECK(stop->payload.find("thread:1;") != std::string::npos);

  client.close();
  polling = false;
  poll_thread.join();
  server.stop();
}

TEST_CASE("server responds to memory region info queries") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto ok = send_packet(server, *transport_ptr, "qMemoryRegionInfo:1000");
  REQUIRE(ok.packets.size() == 1);
  CHECK(
      ok.packets[0].payload ==
      "start:0000000000001000;size:0000000000000100;permissions:rwx;name:74657374;type:stack;"
  );

  auto miss = send_packet(server, *transport_ptr, "qMemoryRegionInfo:0");
  REQUIRE(miss.packets.size() == 1);
  CHECK(miss.packets[0].payload == "start:0000000000000000;size:0000000000001000;");
}

TEST_CASE("server checks thread liveness") {
  mock_state state;
  mock_components target(state);
  state.threads = {1, 2};
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto alive = send_packet(server, *transport_ptr, "T1");
  REQUIRE(alive.packets.size() == 1);
  CHECK(alive.packets[0].payload == "OK");

  auto dead = send_packet(server, *transport_ptr, "T3");
  REQUIRE(dead.packets.size() == 1);
  CHECK(dead.packets[0].payload == "E16");
}

TEST_CASE("server handles interrupt packets") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  std::string interrupt(1, gdbstub::rsp::interrupt_char);
  transport_ptr->push_incoming(interrupt);
  server.poll(std::chrono::milliseconds(0));

  CHECK(state.interrupt_called);
}

TEST_CASE("server responds to qStructuredDataPlugins") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qStructuredDataPlugins");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "[]");
}

TEST_CASE("server responds to QEnableErrorStrings") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "QEnableErrorStrings");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "OK");
}

TEST_CASE("server responds to qShlibInfoAddr when available") {
  mock_state state;
  mock_components target(state);
  gdbstub::shlib_info info;
  info.info_addr = 0x11223344;
  state.shlib = info;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qShlibInfoAddr");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "11223344");
}

TEST_CASE("server responds to jGetLoadedDynamicLibrariesInfos") {
  mock_state state;
  mock_components target(state);
  state.lldb_loaded_libraries_json = "{\"images\":[{\"id\":1}]}";

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto probe = send_packet(server, *transport_ptr, "jGetLoadedDynamicLibrariesInfos:");
  REQUIRE(probe.ack_count == 1);
  REQUIRE(probe.packets.size() == 1);
  CHECK(probe.packets[0].payload == "OK");

  auto out = send_packet(server, *transport_ptr, "jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true}");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  std::string json = unescape_payload(out.packets[0].payload);
  CHECK(json == "{\"images\":[{\"id\":1}]}");
  REQUIRE(state.last_loaded_libraries_request.has_value());
  CHECK(state.last_loaded_libraries_request->kind == gdbstub::lldb::loaded_libraries_request::kind::all);
  CHECK(state.last_loaded_libraries_request->report_load_commands);

  state.lldb_loaded_libraries_json = "{\"images\":[{\"id\":2}]}";
  auto out_addresses = send_packet(
      server,
      *transport_ptr,
      "jGetLoadedDynamicLibrariesInfos:{\"report_load_commands\":false,\"solib_addresses\":[4096,8192]}"
  );
  REQUIRE(out_addresses.ack_count == 1);
  REQUIRE(out_addresses.packets.size() == 1);
  json = unescape_payload(out_addresses.packets[0].payload);
  CHECK(json == "{\"images\":[{\"id\":2}]}");
  REQUIRE(state.last_loaded_libraries_request.has_value());
  CHECK(state.last_loaded_libraries_request->kind == gdbstub::lldb::loaded_libraries_request::kind::addresses);
  CHECK_FALSE(state.last_loaded_libraries_request->report_load_commands);
  REQUIRE(state.last_loaded_libraries_request->addresses.size() == 2);
  CHECK(state.last_loaded_libraries_request->addresses[0] == 0x1000);
  CHECK(state.last_loaded_libraries_request->addresses[1] == 0x2000);

  state.lldb_loaded_libraries_json = "{\"images\":[{\"id\":3}]}";
  auto out_image_list = send_packet(
      server,
      *transport_ptr,
      "jGetLoadedDynamicLibrariesInfos:{\"image_count\":2,\"image_list_address\":12288}"
  );
  REQUIRE(out_image_list.ack_count == 1);
  REQUIRE(out_image_list.packets.size() == 1);
  json = unescape_payload(out_image_list.packets[0].payload);
  CHECK(json == "{\"images\":[{\"id\":3}]}");
  REQUIRE(state.last_loaded_libraries_request.has_value());
  CHECK(state.last_loaded_libraries_request->kind == gdbstub::lldb::loaded_libraries_request::kind::image_list);
  REQUIRE(state.last_loaded_libraries_request->image_count.has_value());
  REQUIRE(state.last_loaded_libraries_request->image_list_address.has_value());
  CHECK(state.last_loaded_libraries_request->image_count.value() == 2);
  CHECK(state.last_loaded_libraries_request->image_list_address.value() == 0x3000);
}

TEST_CASE("server responds to qOffsets with section offsets") {
  mock_state state;
  mock_components target(state);
  state.offsets = gdbstub::offsets_info::section(0x1000, 0x2000, 0x3000);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qOffsets");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "Text=1000;Data=2000;Bss=3000");
}

TEST_CASE("server responds to qOffsets without bss") {
  mock_state state;
  mock_components target(state);
  state.offsets = gdbstub::offsets_info::section(0x1000, 0x2000);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qOffsets");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "Text=1000;Data=2000");
}

TEST_CASE("server responds to qOffsets with segment offsets") {
  mock_state state;
  mock_components target(state);
  state.offsets = gdbstub::offsets_info::segment(0x4000, 0x5000);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qOffsets");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "TextSeg=4000;DataSeg=5000");
}

TEST_CASE("server responds to qOffsets with text segment only") {
  mock_state state;
  mock_components target(state);
  state.offsets = gdbstub::offsets_info::segment(0x4000);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qOffsets");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "TextSeg=4000");
}

TEST_CASE("server returns empty reply for invalid qOffsets data") {
  mock_state state;
  mock_components target(state);
  gdbstub::offsets_info info;
  info.kind = gdbstub::offsets_kind::segment;
  info.text = 0x1000;
  info.bss = 0x20;
  state.offsets = info;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qOffsets");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "");
}

TEST_CASE("server returns empty reply for missing qOffsets data") {
  mock_state state;
  mock_components target(state);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qOffsets");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "");
}

TEST_CASE("server rejects vRun without extended mode") {
  mock_state state;
  mock_components target(state);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "vRun;74657374");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "");
}

TEST_CASE("server handles vRun in extended mode") {
  mock_state state;
  mock_components target(state);
  gdbstub::resume_result result;
  result.state = gdbstub::resume_result::state::stopped;
  result.stop = {gdbstub::stop_kind::signal, 5, 0, 0, 1};
  result.status = gdbstub::target_status::ok;
  state.launch_result = result;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "!");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto out = send_packet(server, *transport_ptr, "vRun;74657374;61726731");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload.rfind("T05", 0) == 0);
  REQUIRE(state.last_launch.has_value());
  CHECK(state.last_launch->filename.value_or("") == "test");
  REQUIRE(state.last_launch->args.size() == 1);
  CHECK(state.last_launch->args[0] == "arg1");

  auto attached = send_packet(server, *transport_ptr, "qAttached");
  REQUIRE(attached.packets.size() == 1);
  CHECK(attached.packets[0].payload == "0");
}

TEST_CASE("server handles vRun without filename") {
  mock_state state;
  mock_components target(state);
  gdbstub::resume_result result;
  result.state = gdbstub::resume_result::state::stopped;
  result.stop = {gdbstub::stop_kind::signal, 5, 0, 0, 1};
  result.status = gdbstub::target_status::ok;
  state.launch_result = result;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "!");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto out = send_packet(server, *transport_ptr, "vRun;;61726731");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload.rfind("T05", 0) == 0);
  REQUIRE(state.last_launch.has_value());
  CHECK(!state.last_launch->filename.has_value());
  REQUIRE(state.last_launch->args.size() == 1);
  CHECK(state.last_launch->args[0] == "arg1");
}

TEST_CASE("server handles vAttach in extended mode") {
  mock_state state;
  mock_components target(state);
  gdbstub::resume_result result;
  result.state = gdbstub::resume_result::state::stopped;
  result.stop = {gdbstub::stop_kind::signal, 5, 0, 0, 1};
  result.status = gdbstub::target_status::ok;
  state.attach_result = result;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "!");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto out = send_packet(server, *transport_ptr, "vAttach;2a");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload.rfind("T05", 0) == 0);
  REQUIRE(state.last_attach_pid.has_value());
  CHECK(state.last_attach_pid.value() == 0x2a);

  auto attached = send_packet(server, *transport_ptr, "qAttached");
  REQUIRE(attached.packets.size() == 1);
  CHECK(attached.packets[0].payload == "1");
}

TEST_CASE("server handles vKill in extended mode") {
  mock_state state;
  mock_components target(state);
  state.kill_status = gdbstub::target_status::ok;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "!");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto out = send_packet(server, *transport_ptr, "vKill;2a");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "OK");
  CHECK(state.last_kill_has_pid);
  CHECK(state.last_kill_pid == 0x2a);
}

TEST_CASE("server handles R restart without reply") {
  mock_state state;
  mock_components target(state);
  gdbstub::resume_result result;
  result.state = gdbstub::resume_result::state::stopped;
  result.stop = {gdbstub::stop_kind::signal, 5, 0, 0, 1};
  result.status = gdbstub::target_status::ok;
  state.restart_result = result;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "!");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto restart = send_packet(server, *transport_ptr, "R00");
  CHECK(restart.ack_count == 1);
  CHECK(restart.packets.empty());
  CHECK(state.restart_called);

  auto out = send_packet(server, *transport_ptr, "?");
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload.rfind("T05", 0) == 0);
}

TEST_CASE("server marks restarted process as launched when running") {
  mock_state state;
  mock_components target(state);
  gdbstub::resume_result result;
  result.state = gdbstub::resume_result::state::running;
  result.status = gdbstub::target_status::ok;
  state.restart_result = result;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "!");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto restart = send_packet(server, *transport_ptr, "R00");
  CHECK(restart.ack_count == 1);
  CHECK(restart.packets.empty());
  CHECK(state.restart_called);

  auto attached = send_packet(server, *transport_ptr, "qAttached");
  REQUIRE(attached.packets.size() == 1);
  CHECK(attached.packets[0].payload == "0");
}

TEST_CASE("server rejects invalid vRun hex") {
  mock_state state;
  mock_components target(state);

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto enable = send_packet(server, *transport_ptr, "!");
  REQUIRE(enable.packets.size() == 1);
  CHECK(enable.packets[0].payload == "OK");

  auto out = send_packet(server, *transport_ptr, "vRun;zz");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "E16");
}

TEST_CASE("server responds to jThreadsInfo") {
  mock_state state;
  mock_components target(state);
  state.threads = {1, 2};
  state.stop_for_threads = gdbstub::stop_reason{gdbstub::stop_kind::signal, 5, 0, 0, std::nullopt};

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "jThreadsInfo");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  auto payload = unescape_payload(out.packets[0].payload);
  CHECK(payload == "[{\"tid\":1,\"reason\":\"signal\",\"signal\":5},{\"tid\":2,\"reason\":\"signal\",\"signal\":5}]");
}

TEST_CASE("server responds to jThreadExtendedInfo") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  std::string request_json = "{\"thread\":1}";
  auto payload = std::string("jThreadExtendedInfo:") + gdbstub::rsp::escape_binary(as_bytes(request_json));
  auto out = send_packet(server, *transport_ptr, payload);
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  auto response = unescape_payload(out.packets[0].payload);
  CHECK(response == "{\"thread\":1}");
}

TEST_CASE("server responds to qXfer memory-map read") {
  mock_state state;
  mock_components target(state);
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qXfer:memory-map:read::0,200");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  std::string expected = "l<memory-map><memory type=\"ram\" start=\"0x1000\" length=\"0x100\" permissions=\"rwx\"/></memory-map>";
  CHECK(out.packets[0].payload == expected);
}

TEST_CASE("server supports binary memory read") {
  mock_state state;
  mock_components target(state);
  state.memory[0x100] = std::byte{'A'};
  state.memory[0x101] = std::byte{'$'};
  state.memory[0x102] = std::byte{'#'};
  state.memory[0x103] = std::byte{'}'};

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_target(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "x100,4");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  auto payload = unescape_payload(out.packets[0].payload);
  CHECK(payload == "A$#}");
}
