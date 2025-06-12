#include "../src/gdbstub.hpp"
#include "mock_target.hpp"
#include <iostream>
#include <signal.h>
#include <thread>

MockTarget target;
std::unique_ptr<gdbstub::server<MockTarget>> stub_server;

void signal_handler(int signal) {
  if (stub_server) {
    stub_server->stop();
  }
  exit(0);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
    return 1;
  }

  // Setup signal handling
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  int port = std::atoi(argv[1]);
  std::string address = "127.0.0.1:" + std::string(argv[1]);

  // Output ready signal immediately
  std::cout << "GDBSTUB_LISTENING_ON_PORT:" << port << std::endl;
  std::cout.flush();

  try {
    gdbstub::arch_info arch = {
        .target_desc = MockTarget::riscv32_target_xml,
        .xml_architecture_name = "org.gnu.gdb.riscv.cpu",
        .osabi = "bare",
        .cpu_count = 1,
        .reg_count = 33,
        .pc_reg_num = 32,
        .swap_registers_endianness = true
    };

    stub_server = std::make_unique<gdbstub::server<MockTarget>>(target, arch);

    if (!stub_server->listen(address.c_str())) {
      std::cerr << "Failed to listen on " << address << std::endl;
      return 1;
    }

    stub_server->serve_forever();

  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}