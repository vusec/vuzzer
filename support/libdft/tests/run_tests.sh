#!/bin/bash

PIN=$PIN_ROOT/pin
PIN_OPTS='-injection child -follow_execv'
TEST_TOOL=libdft_test_tool.so

TESTS=$(find . -maxdepth 1 ! -name "test_wet_*" -name "test_*" -executable)

for TEST in $TESTS; do
    $PIN $PIN_OPTS -t "$TEST_TOOL" -- "$TEST"
done
