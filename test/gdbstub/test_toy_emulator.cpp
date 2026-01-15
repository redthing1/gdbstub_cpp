#include "doctest/doctest.hpp"

#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>

#include "gdbstub/server.hpp"
#include "gdbstub/tcp_test_client.hpp"
#include "gdbstub/transport_tcp.hpp"
#include "gdbstub_tool/toy_emulator.hpp"

namespace {

std::string make_target_xml(int reg_bits, int reg_count, int pc_reg) {
  std::string xml;
  xml.reserve(256);
  xml += "<target version=\"1.0\">";
  xml += "<architecture>toy</architecture>";
  xml += "<feature name=\"org.gnu.gdb.toy\">";
  for (int i = 0; i < reg_count; ++i) {
    xml += "<reg name=\"";
    if (i == pc_reg) {
      xml += "pc";
    } else {
      xml += "r";
      xml += std::to_string(i);
    }
    xml += "\" bitsize=\"";
    xml += std::to_string(reg_bits);
    xml += "\" regnum=\"";
    xml += std::to_string(i);
    xml += "\"";
    if (i == pc_reg) {
      xml += " type=\"code_ptr\"";
    }
    xml += "/>";
  }
  xml += "</feature></target>";
  return xml;
}

template <typename RegT>
gdbstub::arch_spec make_arch_spec(const gdbstub::toy::emulator<RegT>& emu) {
  gdbstub::arch_spec arch;
  arch.reg_count = static_cast<int>(emu.reg_count());
  arch.pc_reg_num = emu.pc_reg_num();
  arch.target_xml = make_target_xml(static_cast<int>(sizeof(RegT) * 8), arch.reg_count, arch.pc_reg_num);
  arch.xml_arch_name = "org.gnu.gdb.toy";
  arch.osabi = "none";
  return arch;
}

template <typename RegT>
gdbstub::server make_server(gdbstub::toy::emulator<RegT>& emu) {
  auto transport = std::make_unique<gdbstub::transport_tcp>();
  auto arch = make_arch_spec(emu);
  gdbstub::target_handles handles{emu, emu, emu};
  handles.breakpoints = &emu;
  handles.memory = &emu;
  handles.threads = &emu;
  handles.host = &emu;
  handles.process = &emu;
  handles.shlib = &emu;
  return gdbstub::server(handles, arch, std::move(transport));
}

} // namespace

TEST_CASE("toy emulator 32-bit blocking stops at breakpoint") {
  gdbstub::toy::emulator<uint32_t>::options options;
  options.mode = gdbstub::toy::execution_mode::blocking;
  options.reg_count = 4;
  options.pc_reg_num = 0;
  options.start_pc = 0x1000;
  options.max_steps = 16;

  gdbstub::toy::emulator<uint32_t> emu(options);
  auto server = make_server(emu);

  constexpr std::string_view k_host = "127.0.0.1";
  auto port = gdbstub::test::listen_on_available_port(server, k_host, 44000, 200);
  REQUIRE(port.has_value());

  std::atomic<bool> accepted{false};
  std::thread accept_thread([&]() { accepted = server.wait_for_connection(); });

  gdbstub::test::tcp_client client;
  REQUIRE(client.connect(k_host, *port));
  accept_thread.join();
  REQUIRE(accepted.load());

  REQUIRE(client.send_packet("Z0,1008,4"));
  auto bp = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(200));
  REQUIRE(bp.has_value());
  CHECK(bp->payload == "OK");

  REQUIRE(client.send_packet("c"));
  auto stop = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(300));
  REQUIRE(stop.has_value());
  CHECK(stop->payload.rfind("T05", 0) == 0);

  REQUIRE(client.send_packet("p0"));
  auto pc = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(200));
  REQUIRE(pc.has_value());
  CHECK(pc->payload == "08100000");

  client.close();
  server.stop();
}

TEST_CASE("toy emulator 32-bit polling stops via poll_stop") {
  gdbstub::toy::emulator<uint32_t>::options options;
  options.mode = gdbstub::toy::execution_mode::polling;
  options.reg_count = 4;
  options.pc_reg_num = 0;
  options.start_pc = 0x2000;
  options.max_steps = 32;

  gdbstub::toy::emulator<uint32_t> emu(options);
  auto server = make_server(emu);

  constexpr std::string_view k_host = "127.0.0.1";
  auto port = gdbstub::test::listen_on_available_port(server, k_host, 44200, 200);
  REQUIRE(port.has_value());

  std::atomic<bool> accepted{false};
  std::thread accept_thread([&]() { accepted = server.wait_for_connection(); });

  gdbstub::test::tcp_client client;
  REQUIRE(client.connect(k_host, *port));
  accept_thread.join();
  REQUIRE(accepted.load());

  REQUIRE(client.send_packet("Z0,200c,4"));
  auto bp = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(200));
  REQUIRE(bp.has_value());
  CHECK(bp->payload == "OK");

  REQUIRE(client.send_packet("c"));
  auto stop = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(300));
  REQUIRE(stop.has_value());
  CHECK(stop->payload.rfind("T05", 0) == 0);

  client.close();
  server.stop();
}

TEST_CASE("toy emulator 32-bit async notifies stop") {
  gdbstub::toy::emulator<uint32_t>::options options;
  options.mode = gdbstub::toy::execution_mode::async;
  options.reg_count = 4;
  options.pc_reg_num = 0;
  options.start_pc = 0x3000;
  options.max_steps = 32;

  gdbstub::toy::emulator<uint32_t> emu(options);
  auto server = make_server(emu);

  emu.set_async_callback([&server](const gdbstub::stop_reason& reason) { server.notify_stop(reason); });

  constexpr std::string_view k_host = "127.0.0.1";
  auto port = gdbstub::test::listen_on_available_port(server, k_host, 44400, 200);
  REQUIRE(port.has_value());

  std::atomic<bool> accepted{false};
  std::thread accept_thread([&]() { accepted = server.wait_for_connection(); });

  gdbstub::test::tcp_client client;
  REQUIRE(client.connect(k_host, *port));
  accept_thread.join();
  REQUIRE(accepted.load());

  REQUIRE(client.send_packet("Z0,3008,4"));
  auto bp = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(200));
  REQUIRE(bp.has_value());
  CHECK(bp->payload == "OK");

  REQUIRE(client.send_packet("c"));
  auto stop = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(400));
  REQUIRE(stop.has_value());
  CHECK(stop->payload.rfind("T05", 0) == 0);

  client.close();
  server.stop();
}

TEST_CASE("toy emulator 64-bit reads and writes registers") {
  gdbstub::toy::emulator<uint64_t>::options options;
  options.mode = gdbstub::toy::execution_mode::blocking;
  options.reg_count = 2;
  options.pc_reg_num = 1;
  options.start_pc = 0x1000;

  gdbstub::toy::emulator<uint64_t> emu(options);
  emu.set_reg(0, 0x1122334455667788ULL);

  auto server = make_server(emu);

  constexpr std::string_view k_host = "127.0.0.1";
  auto port = gdbstub::test::listen_on_available_port(server, k_host, 44600, 200);
  REQUIRE(port.has_value());

  std::atomic<bool> accepted{false};
  std::thread accept_thread([&]() { accepted = server.wait_for_connection(); });

  gdbstub::test::tcp_client client;
  REQUIRE(client.connect(k_host, *port));
  accept_thread.join();
  REQUIRE(accepted.load());

  REQUIRE(client.send_packet("p0"));
  auto read = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(200));
  REQUIRE(read.has_value());
  CHECK(read->payload == "8877665544332211");

  REQUIRE(client.send_packet("P0=0100000000000000"));
  auto write = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(200));
  REQUIRE(write.has_value());
  CHECK(write->payload == "OK");

  REQUIRE(client.send_packet("p0"));
  auto read_back = gdbstub::test::wait_for_reply(server, client, std::chrono::milliseconds(200));
  REQUIRE(read_back.has_value());
  CHECK(read_back->payload == "0100000000000000");

  client.close();
  server.stop();
}
