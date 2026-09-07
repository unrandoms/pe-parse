/*
 * Tests for IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT parsing (GH#144).
 *
 * Fixture: tests/assets/delay_import.exe
 *   A hand-crafted PE32+ (x86-64) binary with a single delay-load descriptor
 *   for "TESTDLL.DLL" exporting one function: "TestFunction".
 */

#include <pe-parse/parse.h>

#include <catch2/catch.hpp>

#include "filesystem_compat.h"

namespace peparse {

TEST_CASE("delay import directory is parsed (GH#144)", "[delay_import]") {
  fs::path path = fs::path(ASSETS_DIR) / "delay_import.exe";
  parsed_pe *p = ParsePEFromFile(path.string().c_str());

  REQUIRE(p != nullptr);

  SECTION("exactly one delay-import symbol is found") {
    std::vector<std::pair<std::string, std::string>> syms;

    IterDelayImpVAString(
        p,
        [](void *cbd,
           const VA & /*addr*/,
           const std::string &mod,
           const std::string &sym) -> int {
          auto *v =
              reinterpret_cast<std::vector<std::pair<std::string, std::string>> *>(
                  cbd);
          v->emplace_back(mod, sym);
          return 0;
        },
        &syms);

    REQUIRE(syms.size() == 1);
    REQUIRE(syms[0].first == "TESTDLL.DLL");
    REQUIRE(syms[0].second == "TestFunction");
  }

  SECTION("regular imports are not affected") {
    std::size_t imp_count = 0;

    IterImpVAString(
        p,
        [](void *cbd, const VA &, const std::string &, const std::string &)
            -> int {
          (*reinterpret_cast<std::size_t *>(cbd))++;
          return 0;
        },
        &imp_count);

    // The fixture has no regular import directory.
    REQUIRE(imp_count == 0);
  }

  DestructParsedPE(p);
}

TEST_CASE("PE without delay imports yields empty delay-import list",
          "[delay_import]") {
  fs::path path = fs::path(ASSETS_DIR) / "example.exe";
  parsed_pe *p = ParsePEFromFile(path.string().c_str());

  REQUIRE(p != nullptr);

  std::size_t count = 0;
  IterDelayImpVAString(
      p,
      [](void *cbd, const VA &, const std::string &, const std::string &)
          -> int {
        (*reinterpret_cast<std::size_t *>(cbd))++;
        return 0;
      },
      &count);

  REQUIRE(count == 0);

  DestructParsedPE(p);
}

} // namespace peparse
