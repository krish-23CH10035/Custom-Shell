#!/bin/bash

set -e

echo "Running Custom Shell tests..."

echo "Testing build..."
make

echo "Testing basic command..."
echo "echo hello" | ./mysh | grep "hello"

echo "Testing pwd..."
echo "pwd" | ./mysh | grep "/"

echo "Testing pipeline..."
echo "echo hello | wc -l" | ./mysh

echo "Testing history..."
printf "pwd\nhistory\n" | ./mysh

echo "Testing invalid command..."
printf "this_command_does_not_exist\nexit\n" | ./mysh

echo "All basic tests passed!"