#include <iostream>

#include "gdbstub/gdbstub.hpp"

int main() {
  std::cout << "gdbstub_cpp version " << gdbstub::version() << "\n";
  return 0;
}
