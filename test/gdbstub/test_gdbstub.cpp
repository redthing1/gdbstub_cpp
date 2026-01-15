#include "doctest/doctest.hpp"

#include "gdbstub/gdbstub.hpp"

TEST_CASE("version is non-empty") {
  CHECK_FALSE(gdbstub::version().empty());
}
