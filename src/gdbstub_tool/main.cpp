#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#include "args/args.hpp"
#include "gdbstub/gdbstub.hpp"
#include "gdbstub/server.hpp"
#include "gdbstub/transport_tcp.hpp"
#include "gdbstub_tool/toy_emulator.hpp"

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
int run_server(std::string_view address, gdbstub::toy::execution_mode mode, size_t max_steps, std::string triple) {
  typename gdbstub::toy::emulator<RegT>::options options;
  options.mode = mode;
  options.max_steps = max_steps;
  if (triple.empty()) {
    options.triple = sizeof(RegT) == 4 ? "riscv32-unknown-elf" : "riscv64-unknown-elf";
  } else {
    options.triple = std::move(triple);
  }

  gdbstub::toy::emulator<RegT> emu(options);

  gdbstub::arch_spec arch;
  arch.reg_count = static_cast<int>(emu.reg_count());
  arch.pc_reg_num = emu.pc_reg_num();
  arch.target_xml = make_target_xml(static_cast<int>(sizeof(RegT) * 8), arch.reg_count, arch.pc_reg_num);
  arch.xml_arch_name = "org.gnu.gdb.toy";
  arch.osabi = options.osabi;

  auto transport = std::make_unique<gdbstub::transport_tcp>();
  gdbstub::target_handles handles{emu, emu, emu};
  handles.breakpoints = &emu;
  handles.memory = &emu;
  handles.threads = &emu;
  handles.host = &emu;
  handles.process = &emu;
  handles.shlib = &emu;
  gdbstub::server server(handles, arch, std::move(transport));
  if (!server.listen(address)) {
    std::cerr << "failed to listen on " << address << "\n";
    return 1;
  }

  if (mode == gdbstub::toy::execution_mode::async) {
    emu.set_async_callback([&server](const gdbstub::stop_reason& reason) { server.notify_stop(reason); });
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

  if (arch_bits == 32) {
    return run_server<uint32_t>(address, *parsed_mode, static_cast<size_t>(max_steps), std::move(triple_text));
  }
  return run_server<uint64_t>(address, *parsed_mode, static_cast<size_t>(max_steps), std::move(triple_text));
}
