#!/bin/sh

clang-format -i $(git ls-files | grep -E '.(c|h)pp$')
