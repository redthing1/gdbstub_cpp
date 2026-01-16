#include "doctest/doctest.hpp"

#include <array>
#include <cstdint>

#include "gdbstub_tool/toy/layout.hpp"
#include "gdbstub_tool/toy/machine.hpp"
#include "gdbstub_tool/toy/types.hpp"

namespace {

gdbstub::toy::config make_config(uint32_t reg_bits, size_t reg_count) {
  gdbstub::toy::config cfg;
  cfg.reg_bits = reg_bits;
  cfg.reg_count = reg_count;
  cfg.pc_reg_num = 0;
  cfg.start_pc = 0x1000;
  cfg.instruction_size = 4;
  cfg.memory_size = 0x100;
  return cfg;
}

} // namespace

TEST_CASE("toy layout exposes register sizes") {
  auto cfg = make_config(32, 2);
  gdbstub::toy::layout layout(cfg);

  CHECK(layout.reg_count() == 2);
  CHECK(layout.reg_size(0) == 4);
  CHECK(layout.reg_size(1) == 4);
  CHECK(layout.reg_size(2) == 0);
}

TEST_CASE("toy machine masks register width") {
  auto cfg = make_config(32, 1);
  gdbstub::toy::machine machine(cfg);

  machine.set_reg(0, 0x1'0000'0001ULL);
  CHECK(machine.reg_value(0) == 0x00000001ULL);
}

TEST_CASE("toy machine reads and writes memory") {
  auto cfg = make_config(32, 1);
  gdbstub::toy::machine machine(cfg);

  std::array<std::byte, 4> bytes = {std::byte{'A'}, std::byte{'B'}, std::byte{'C'}, std::byte{'D'}};
  CHECK(machine.write_mem(0x10, bytes) == gdbstub::target_status::ok);

  std::array<std::byte, 4> out{};
  CHECK(machine.read_mem(0x10, out) == gdbstub::target_status::ok);
  CHECK(out == bytes);

  std::array<std::byte, 4> overflow{};
  CHECK(machine.read_mem(cfg.memory_size - 1, overflow) == gdbstub::target_status::fault);
}

TEST_CASE("toy machine reports breakpoints") {
  auto cfg = make_config(32, 2);
  cfg.start_pc = 0x2000;
  gdbstub::toy::machine machine(cfg);

  machine.add_breakpoint(0x2000);
  auto stop = machine.stop_if_breakpoint(1);
  REQUIRE(stop.has_value());
  CHECK(stop->kind == gdbstub::stop_kind::sw_break);
  CHECK(stop->addr == 0x2000);
}

TEST_CASE("toy machine steps and advances PC") {
  auto cfg = make_config(32, 1);
  cfg.start_pc = 0x3000;
  cfg.instruction_size = 4;
  gdbstub::toy::machine machine(cfg);

  auto stop = machine.step_and_check(1);
  CHECK_FALSE(stop.has_value());
  CHECK(machine.pc() == 0x3004);
}
