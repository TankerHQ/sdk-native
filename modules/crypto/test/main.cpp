#define DOCTEST_CONFIG_IMPLEMENT

#include <doctest/doctest.h>

int main(int argc, char* argv[])
{
  doctest::Context context(argc, argv);

  return context.run();
}
