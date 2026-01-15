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
#include <vector>

#include "gdbstub/rsp_core.hpp"
#include "gdbstub/server.hpp"
#include "gdbstub/tcp_test_client.hpp"
#include "gdbstub/transport.hpp"
#include "gdbstub/transport_tcp.hpp"

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

struct mock_target : gdbstub::register_access,
                     gdbstub::memory_access,
                     gdbstub::run_control,
                     gdbstub::breakpoint_access,
                     gdbstub::memory_map,
                     gdbstub::host_info_provider,
                     gdbstub::process_info_provider,
                     gdbstub::thread_access,
                     gdbstub::shlib_info_provider {
  std::array<uint32_t, 3> regs{};
  std::vector<std::byte> memory = std::vector<std::byte>(0x2000);
  std::vector<uint64_t> threads = {1};
  std::optional<gdbstub::stop_reason> stop_for_threads;
  std::optional<gdbstub::shlib_info> shlib;

  enum class resume_behavior { stop_immediately, run };

  resume_behavior resume_behavior = resume_behavior::stop_immediately;

  mock_target() { regs[2] = 0x1000; }

  size_t reg_size(int) const override { return 4; }

  gdbstub::target_status read_reg(int regno, std::span<std::byte> out) override {
    if (regno < 0 || regno >= static_cast<int>(regs.size()) || out.size() != 4) {
      return gdbstub::target_status::invalid;
    }
    uint32_t value = regs[static_cast<size_t>(regno)];
    out[0] = std::byte(value & 0xff);
    out[1] = std::byte((value >> 8) & 0xff);
    out[2] = std::byte((value >> 16) & 0xff);
    out[3] = std::byte((value >> 24) & 0xff);
    return gdbstub::target_status::ok;
  }

  gdbstub::target_status write_reg(int regno, std::span<const std::byte> data) override {
    if (regno < 0 || regno >= static_cast<int>(regs.size()) || data.size() != 4) {
      return gdbstub::target_status::invalid;
    }
    uint32_t value = static_cast<uint32_t>(data[0]) |
                     (static_cast<uint32_t>(data[1]) << 8) |
                     (static_cast<uint32_t>(data[2]) << 16) |
                     (static_cast<uint32_t>(data[3]) << 24);
    regs[static_cast<size_t>(regno)] = value;
    return gdbstub::target_status::ok;
  }

  gdbstub::target_status read_mem(uint64_t addr, std::span<std::byte> out) override {
    if (addr + out.size() > memory.size()) {
      return gdbstub::target_status::fault;
    }
    std::memcpy(out.data(), memory.data() + addr, out.size());
    return gdbstub::target_status::ok;
  }

  gdbstub::target_status write_mem(uint64_t addr, std::span<const std::byte> data) override {
    if (addr + data.size() > memory.size()) {
      return gdbstub::target_status::fault;
    }
    std::memcpy(memory.data() + addr, data.data(), data.size());
    return gdbstub::target_status::ok;
  }

  gdbstub::resume_result resume(const gdbstub::resume_request& request) override {
    if (request.action == gdbstub::resume_action::step) {
      regs[2] += 4;
    }

    gdbstub::resume_result result;
    if (resume_behavior == resume_behavior::run) {
      result.state = gdbstub::resume_result::state::running;
      return result;
    }

    result.state = gdbstub::resume_result::state::stopped;
    result.stop = {gdbstub::stop_kind::signal, 5, 0, 0, 1};
    return result;
  }

  gdbstub::target_status set_breakpoint(const gdbstub::breakpoint_access::spec&) override {
    return gdbstub::target_status::ok;
  }
  gdbstub::target_status remove_breakpoint(const gdbstub::breakpoint_access::spec&) override {
    return gdbstub::target_status::ok;
  }

  std::optional<gdbstub::memory_region> region_for(uint64_t addr) override {
    if (addr >= 0x1000 && addr < 0x1100) {
      return gdbstub::memory_region{0x1000, 0x100, "rwx"};
    }
    return std::nullopt;
  }

  std::vector<gdbstub::memory_region> regions() override {
    return {gdbstub::memory_region{0x1000, 0x100, "rwx"}};
  }

  std::optional<gdbstub::host_info> get_host_info() override {
    return gdbstub::host_info{
        "riscv32-unknown-elf", "little", 4, "mock-host", "1.0", "build", "kernel", std::nullopt};
  }

  std::optional<gdbstub::process_info> get_process_info() override {
    return gdbstub::process_info{42, "riscv32-unknown-elf", "little", 4, "bare"};
  }

  std::vector<uint64_t> thread_ids() override { return threads; }
  uint64_t current_thread() const override { return 1; }
  gdbstub::target_status set_current_thread(uint64_t) override { return gdbstub::target_status::ok; }
  std::optional<uint64_t> thread_pc(uint64_t) override { return regs[2]; }
  std::optional<std::string> thread_name(uint64_t) override { return std::nullopt; }
  std::optional<gdbstub::stop_reason> thread_stop_reason(uint64_t) override { return stop_for_threads; }

  std::optional<gdbstub::shlib_info> get_shlib_info() override { return shlib; }
};

struct parsed_output {
  std::vector<gdbstub::rsp::input_event> packets;
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
    } else if (event.kind == gdbstub::rsp::event_kind::packet) {
      out.packets.push_back(std::move(event));
    }
  }
  return out;
}

gdbstub::target_handles make_handles(mock_target& target) {
  gdbstub::target_handles handles{target, target, target};
  handles.breakpoints = &target;
  handles.memory = &target;
  handles.threads = &target;
  handles.host = &target;
  handles.process = &target;
  handles.shlib = &target;
  return handles;
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
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;
  arch.target_xml = "<target></target>";
  arch.xml_arch_name = "org.gnu.gdb.riscv.cpu";

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

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
}

TEST_CASE("server reports gdbserver version") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto output = send_packet(server, *transport_ptr, "qGDBServerVersion");
  REQUIRE(output.packets.size() == 1);
  CHECK(output.packets[0].payload.find("name:gdbstub_cpp") != std::string::npos);
  CHECK(output.packets[0].payload.find("version:") != std::string::npos);
}

TEST_CASE("server responds to qThreadStopInfo") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto output = send_packet(server, *transport_ptr, "qThreadStopInfo1");
  REQUIRE(output.packets.size() == 1);
  CHECK(output.packets[0].payload.rfind("T05", 0) == 0);
  CHECK(output.packets[0].payload.find("thread:1;") != std::string::npos);
}

TEST_CASE("server reads and writes registers") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto write_out = send_packet(server, *transport_ptr, "P1=78563412");
  REQUIRE(write_out.packets.size() == 1);
  CHECK(write_out.packets[0].payload == "OK");

  auto read_out = send_packet(server, *transport_ptr, "p1");
  REQUIRE(read_out.packets.size() == 1);
  CHECK(read_out.packets[0].payload == "78563412");
}

TEST_CASE("server reads memory") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  target.memory[0x1000] = std::byte{0xaa};
  target.memory[0x1001] = std::byte{0xbb};
  target.memory[0x1002] = std::byte{0xcc};
  target.memory[0x1003] = std::byte{0xdd};

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "m1000,4");
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "aabbccdd");
}

TEST_CASE("server handles no-ack mode") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

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
}

TEST_CASE("server serves target xml via qXfer") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;
  arch.target_xml = "<target>abc</target>";
  arch.xml_arch_name = "org.gnu.gdb.riscv.cpu";

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qXfer:features:read:target.xml:0,10");
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload[0] == 'm');
}

TEST_CASE("server sets breakpoints and continues") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto bp = send_packet(server, *transport_ptr, "Z0,1000,4");
  REQUIRE(bp.packets.size() == 1);
  CHECK(bp.packets[0].payload == "OK");

  auto cont = send_packet(server, *transport_ptr, "c");
  REQUIRE(cont.packets.size() == 1);
  CHECK(cont.packets[0].payload.rfind("T", 0) == 0);
}

TEST_CASE("tcp polling integration serves packets") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;
  arch.target_xml = "<target></target>";
  arch.xml_arch_name = "org.gnu.gdb.riscv.cpu";

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

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
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

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
  mock_target target;
  target.resume_behavior = mock_target::resume_behavior::run;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;
  arch.pc_reg_num = 2;

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

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

TEST_CASE("server responds to qStructuredDataPlugins") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qStructuredDataPlugins");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "[]");
}

TEST_CASE("server responds to QEnableErrorStrings") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "QEnableErrorStrings");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "OK");
}

TEST_CASE("server responds to qShlibInfoAddr when available") {
  mock_target target;
  gdbstub::shlib_info info;
  info.info_addr = 0x11223344;
  target.shlib = info;

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qShlibInfoAddr");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  CHECK(out.packets[0].payload == "11223344");
}

TEST_CASE("server responds to jThreadsInfo") {
  mock_target target;
  target.threads = {1, 2};
  target.stop_for_threads = gdbstub::stop_reason{gdbstub::stop_kind::signal, 5, 0, 0, std::nullopt};

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "jThreadsInfo");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  auto payload = unescape_payload(out.packets[0].payload);
  CHECK(payload == "[{\"tid\":1,\"reason\":\"signal\",\"signal\":5},{\"tid\":2,\"reason\":\"signal\",\"signal\":5}]");
}

TEST_CASE("server responds to jThreadExtendedInfo") {
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

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
  mock_target target;
  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "qXfer:memory-map:read::0,200");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  std::string expected = "l<memory-map><memory type=\"ram\" start=\"0x1000\" length=\"0x100\" permissions=\"rwx\"/></memory-map>";
  CHECK(out.packets[0].payload == expected);
}

TEST_CASE("server supports binary memory read") {
  mock_target target;
  target.memory[0x100] = std::byte{'A'};
  target.memory[0x101] = std::byte{'$'};
  target.memory[0x102] = std::byte{'#'};
  target.memory[0x103] = std::byte{'}'};

  gdbstub::arch_spec arch;
  arch.reg_count = 3;

  auto transport = std::make_unique<loopback_transport>();
  auto* transport_ptr = transport.get();
  gdbstub::server server(make_handles(target), arch, std::move(transport));

  REQUIRE(server.listen("loop"));
  REQUIRE(server.wait_for_connection());

  auto out = send_packet(server, *transport_ptr, "x100,4");
  REQUIRE(out.ack_count == 1);
  REQUIRE(out.packets.size() == 1);
  auto payload = unescape_payload(out.packets[0].payload);
  CHECK(payload == "A$#}");
}
