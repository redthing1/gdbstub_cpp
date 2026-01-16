#include "doctest/doctest.hpp"

#include <chrono>
#include <string_view>

#include "gdbstub/tcp_test_client.hpp"
#include "gdbstub/toy_session.hpp"

namespace {

using namespace std::chrono_literals;

constexpr std::string_view k_host = "127.0.0.1";

constexpr auto k_default_timeout = 200ms;
constexpr auto k_async_timeout = 400ms;

constexpr uint16_t k_port_base = 44000;
constexpr uint16_t k_port_sweep = 200;

[[nodiscard]] gdbstub::toy::config make_config(uint32_t reg_bits, gdbstub::toy::execution_mode mode) {
  gdbstub::toy::config cfg;
  cfg.reg_bits = reg_bits;
  cfg.mode = mode;
  return cfg;
}

gdbstub::test::client_reply send_and_wait(
    gdbstub::test::toy_session& session,
    std::string_view payload,
    std::chrono::milliseconds timeout = k_default_timeout
) {
  REQUIRE(session.client().send_packet(payload));
  auto reply = gdbstub::test::wait_for_reply(session.server(), session.client(), timeout);
  REQUIRE(reply.has_value());
  return *reply;
}

} // namespace

TEST_CASE("toy emulator 32-bit blocking stops at breakpoint") {
  auto cfg = make_config(32, gdbstub::toy::execution_mode::blocking);
  cfg.reg_count = 4;
  cfg.pc_reg_num = 0;
  cfg.start_pc = 0x1000;
  cfg.max_steps = 16;

  gdbstub::test::toy_session session(cfg);
  REQUIRE(session.listen_and_connect(k_host, k_port_base, k_port_sweep));

  auto bp = send_and_wait(session, "Z0,1008,4");
  CHECK(bp.payload == "OK");

  auto stop = send_and_wait(session, "c", 300ms);
  CHECK(stop.payload.rfind("T05", 0) == 0);

  auto pc = send_and_wait(session, "p0");
  CHECK(pc.payload == "08100000");
}

TEST_CASE("toy emulator 32-bit polling stops via poll_stop") {
  auto cfg = make_config(32, gdbstub::toy::execution_mode::polling);
  cfg.reg_count = 4;
  cfg.pc_reg_num = 0;
  cfg.start_pc = 0x2000;
  cfg.max_steps = 32;

  gdbstub::test::toy_session session(cfg);
  REQUIRE(session.listen_and_connect(k_host, k_port_base + 200, k_port_sweep));

  auto bp = send_and_wait(session, "Z0,200c,4");
  CHECK(bp.payload == "OK");

  auto stop = send_and_wait(session, "c", 300ms);
  CHECK(stop.payload.rfind("T05", 0) == 0);
}

TEST_CASE("toy emulator 32-bit async notifies stop") {
  auto cfg = make_config(32, gdbstub::toy::execution_mode::async);
  cfg.reg_count = 4;
  cfg.pc_reg_num = 0;
  cfg.start_pc = 0x3000;
  cfg.max_steps = 32;

  gdbstub::test::toy_session session(cfg);
  REQUIRE(session.listen_and_connect(k_host, k_port_base + 400, k_port_sweep));

  auto bp = send_and_wait(session, "Z0,3008,4");
  CHECK(bp.payload == "OK");

  auto stop = send_and_wait(session, "c", k_async_timeout);
  CHECK(stop.payload.rfind("T05", 0) == 0);
}

TEST_CASE("toy emulator 64-bit reads and writes registers") {
  auto cfg = make_config(64, gdbstub::toy::execution_mode::blocking);
  cfg.reg_count = 2;
  cfg.pc_reg_num = 1;
  cfg.start_pc = 0x1000;

  gdbstub::test::toy_session session(cfg);
  session.target().set_reg(0, 0x1122334455667788ULL);
  REQUIRE(session.listen_and_connect(k_host, k_port_base + 600, k_port_sweep));

  auto read = send_and_wait(session, "p0");
  CHECK(read.payload == "8877665544332211");

  auto write = send_and_wait(session, "P0=0100000000000000");
  CHECK(write.payload == "OK");

  auto read_back = send_and_wait(session, "p0");
  CHECK(read_back.payload == "0100000000000000");
}

TEST_CASE("toy emulator reports multiple threads and honors selection") {
  auto cfg = make_config(32, gdbstub::toy::execution_mode::blocking);
  cfg.thread_ids = {1, 2, 3};

  gdbstub::test::toy_session session(cfg);
  REQUIRE(session.listen_and_connect(k_host, k_port_base + 800, k_port_sweep));

  auto list = send_and_wait(session, "qfThreadInfo");
  CHECK(list.payload == "m1,2,3");

  auto set_thread = send_and_wait(session, "Hc2");
  CHECK(set_thread.payload == "OK");

  auto current = send_and_wait(session, "qC");
  CHECK(current.payload == "QC2");
}
