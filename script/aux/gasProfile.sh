#!/bin/bash

LOG_FILE=$(date +%Y-%m-%d_%H:%M)

echo "------ Generating gas reports ------"

forge snapshot --snap gas_reports/$LOG_FILE.snap.out

forge test --silent --gas-report >> gas_reports/$LOG_FILE.gas.out
