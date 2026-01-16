#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#include "args/args.hpp"
#include "gdbstub/gdbstub.hpp"
#include "gdbstub/server.hpp"
#include "gdbstub/transport_tcp.hpp"
#include "gdbstub_tool/toy/target.hpp"

namespace {

std::optional<gdbstub::toy::execution_mode> parse_mode(std::string_view text) {
  if (text == "blocking") {
    return gdbstub::toy::execution_mode::blocking;
  }
  if (text == "polling") {
    return gdbstub::toy::execution_mode::polling;
  }
  if (text == "async") {
    return gdbstub::toy::execution_mode::async;
  }
  return std::nullopt;
}

int run_server(std::string_view address, gdbstub::toy::config cfg) {
  gdbstub::toy::target target(std::move(cfg));

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::server server(target.make_target(), target.make_arch_spec(), std::move(transport));
  if (!server.listen(address)) {
    std::cerr << "failed to listen on " << address << "\n";
    return 1;
  }

  std::cout << "gdbstub_cpp " << gdbstub::version() << "\n";
  std::cout << "listening on " << address << "\n" << std::flush;
  server.serve_forever();
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  args::ArgumentParser parser("gdbstub_cpp toy server");
  args::HelpFlag help(parser, "help", "display this help menu", {'h', "help"});
  args::ValueFlag<std::string> listen(parser, "addr", "listen address", {'l', "listen"});
  args::ValueFlag<std::string> mode(parser, "mode", "execution mode: blocking|polling|async", {'m', "mode"});
  args::ValueFlag<int> arch(parser, "bits", "register width (32 or 64)", {"arch"});
  args::ValueFlag<int> steps(parser, "steps", "max steps before forcing stop", {"max-steps"});
  args::ValueFlag<std::string> triple(parser, "triple", "target triple", {"triple"});

  try {
    parser.ParseCLI(argc, argv);
  } catch (const args::Help&) {
    std::cout << parser;
    return 0;
  } catch (const args::ParseError& err) {
    std::cerr << err.what() << "\n";
    std::cerr << parser;
    return 1;
  }

  std::string address = listen ? args::get(listen) : "127.0.0.1:5555";
  std::string mode_text = mode ? args::get(mode) : "polling";
  int arch_bits = arch ? args::get(arch) : 32;
  int max_steps = steps ? args::get(steps) : 256;
  std::string triple_text = triple ? args::get(triple) : "";

  auto parsed_mode = parse_mode(mode_text);
  if (!parsed_mode) {
    std::cerr << "unknown mode: " << mode_text << "\n";
    return 1;
  }
  if (arch_bits != 32 && arch_bits != 64) {
    std::cerr << "invalid arch: " << arch_bits << "\n";
    return 1;
  }
  if (max_steps <= 0) {
    std::cerr << "max-steps must be positive\n";
    return 1;
  }

  gdbstub::toy::config cfg;
  cfg.mode = *parsed_mode;
  cfg.max_steps = static_cast<size_t>(max_steps);
  cfg.reg_bits = static_cast<uint32_t>(arch_bits);
  if (triple_text.empty()) {
    cfg.triple = arch_bits == 32 ? "riscv32-unknown-elf" : "riscv64-unknown-elf";
  } else {
    cfg.triple = std::move(triple_text);
  }

  return run_server(address, std::move(cfg));
}
