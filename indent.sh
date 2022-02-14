#!/bin/sh

clang-format-13 -i $(git ls-files | grep -E '\.(c|h)pp$')
