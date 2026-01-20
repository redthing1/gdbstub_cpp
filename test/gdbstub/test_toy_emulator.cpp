#include "doctest/doctest.hpp"

#include <chrono>
#include <span>
#include <string_view>

#include "gdbstub/protocol/rsp_core.hpp"
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

gdbstub::test::client_reply wait_for_event(
    gdbstub::test::toy_session& session,
    std::chrono::milliseconds timeout = k_default_timeout
) {
  auto reply = gdbstub::test::wait_for_event(session.server(), session.client(), timeout);
  REQUIRE(reply.has_value());
  return *reply;
}

std::span<const std::byte> as_bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
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

TEST_CASE("toy emulator reverse step and reverse continue") {
  auto cfg = make_config(32, gdbstub::toy::execution_mode::blocking);
  cfg.reg_count = 2;
  cfg.pc_reg_num = 0;
  cfg.start_pc = 0x1000;
  cfg.max_steps = 8;
  cfg.history_limit = 8;

  gdbstub::test::toy_session session(cfg);
  REQUIRE(session.listen_and_connect(k_host, k_port_base + 500, k_port_sweep));

  auto step1 = send_and_wait(session, "s");
  CHECK(step1.payload.rfind("T05", 0) == 0);
  auto step2 = send_and_wait(session, "s");
  CHECK(step2.payload.rfind("T05", 0) == 0);

  auto back = send_and_wait(session, "bs");
  CHECK(back.payload.rfind("T05", 0) == 0);
  auto pc = send_and_wait(session, "p0");
  CHECK(pc.payload == "04100000");

  auto reverse = send_and_wait(session, "bc");
  CHECK(reverse.payload.find("replaylog:begin;") != std::string::npos);
  auto pc_back = send_and_wait(session, "p0");
  CHECK(pc_back.payload == "00100000");
}

TEST_CASE("toy emulator range stepping stops at range end") {
  auto cfg = make_config(32, gdbstub::toy::execution_mode::blocking);
  cfg.reg_count = 2;
  cfg.pc_reg_num = 0;
  cfg.start_pc = 0x2000;
  cfg.max_steps = 16;

  gdbstub::test::toy_session session(cfg);
  REQUIRE(session.listen_and_connect(k_host, k_port_base + 550, k_port_sweep));

  auto vcont = send_and_wait(session, "vCont;r2000,200c");
  CHECK(vcont.payload.rfind("T05", 0) == 0);

  auto pc = send_and_wait(session, "p0");
  CHECK(pc.payload == "0c200000");
}

TEST_CASE("toy emulator hardware breakpoint and watchpoint") {
  auto cfg = make_config(32, gdbstub::toy::execution_mode::blocking);
  cfg.reg_count = 2;
  cfg.pc_reg_num = 0;
  cfg.start_pc = 0x3000;
  cfg.max_steps = 16;

  gdbstub::test::toy_session session(cfg);
  REQUIRE(session.listen_and_connect(k_host, k_port_base + 900, k_port_sweep));

  auto supported = send_and_wait(session, "qSupported");
  CHECK(supported.payload.find("hwbreak+") != std::string::npos);

  auto hw_bp = send_and_wait(session, "Z1,3008,4");
  CHECK(hw_bp.payload == "OK");

  auto hw_stop = send_and_wait(session, "c");
  CHECK(hw_stop.payload.find("hwbreak:;") != std::string::npos);

  auto watch = send_and_wait(session, "Z2,300d,1");
  CHECK(watch.payload == "OK");

  auto watch_stop = send_and_wait(session, "c");
  CHECK(watch_stop.payload.find("watch:") != std::string::npos);
}

TEST_CASE("toy emulator non-stop async notifications") {
  auto cfg = make_config(32, gdbstub::toy::execution_mode::async);
  cfg.reg_count = 2;
  cfg.pc_reg_num = 0;
  cfg.start_pc = 0x4000;
  cfg.max_steps = 32;

  gdbstub::test::toy_session session(cfg);
  REQUIRE(session.listen_and_connect(k_host, k_port_base + 950, k_port_sweep));

  auto enable = send_and_wait(session, "QNonStop:1");
  CHECK(enable.payload == "OK");

  auto bp = send_and_wait(session, "Z0,4008,4");
  CHECK(bp.payload == "OK");

  auto resume = send_and_wait(session, "c");
  CHECK(resume.payload == "OK");

  auto notify = wait_for_event(session, k_async_timeout);
  CHECK(notify.is_notification);
  CHECK(notify.payload.rfind("Stop:T", 0) == 0);

  auto first = send_and_wait(session, "vStopped");
  CHECK(first.payload.rfind("T", 0) == 0);

  auto second = send_and_wait(session, "vStopped");
  CHECK(second.payload == "OK");
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

TEST_CASE("toy emulator writes and reads memory packets") {
  auto cfg = make_config(32, gdbstub::toy::execution_mode::blocking);
  cfg.reg_count = 2;
  cfg.pc_reg_num = 0;
  cfg.start_pc = 0x1000;

  gdbstub::test::toy_session session(cfg);
  REQUIRE(session.listen_and_connect(k_host, k_port_base + 700, k_port_sweep));

  auto write_hex = send_and_wait(session, "M1010,4:01020304");
  CHECK(write_hex.payload == "OK");

  auto read_hex = send_and_wait(session, "m1010,4");
  CHECK(read_hex.payload == "01020304");

  std::string data = "A$#}";
  std::string payload = "X1014,4:";
  payload += gdbstub::rsp::escape_binary(as_bytes(data));
  auto write_bin = send_and_wait(session, payload);
  CHECK(write_bin.payload == "OK");

  auto read_bin = send_and_wait(session, "x1014,4");
  std::string bin_payload = read_bin.payload;
  gdbstub::rsp::unescape_binary(bin_payload);
  CHECK(bin_payload == "A$#}");
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
