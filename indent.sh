#!/bin/sh

clang-format-11 -i $(git ls-files | grep -E '\.(c|h)pp$')
