#!/bin/sh

clang-format-17 -i $(git ls-files | grep -E '\.(c|h)pp$')
