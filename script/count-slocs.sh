#!/bin/bash

echo "Counting all lines of Solidity files: "
find contracts -name '*.sol' | xargs wc -l
echo
echo "Counting all lines of Solidity files (excluding interfaces): "
find contracts -name '*.sol' ! -path "*/interfaces/*"  | xargs wc -l
