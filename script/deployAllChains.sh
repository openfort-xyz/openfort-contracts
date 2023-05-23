#!/bin/bash

source .env
LOG_FILE=$(date +%Y-%m-%d_%H:%M)"-deploymentAllChains.log"

echo "------ StaticOpenfortDeploy ------ (Goerli)"
forge script StaticOpenfortDeploy --fork-url $GOERLI_RPC -vvvv --verify --broadcast --etherscan-api-key $GOERLI_API_KEY >> $LOG_FILE
echo "------ StaticOpenfortDeploy ------ (Mumbai)"
forge script StaticOpenfortDeploy --fork-url $POLYGON_MUMBAI_RPC -vvvv --verify --broadcast --etherscan-api-key $POLYGON_MUMBAI_KEY >> $LOG_FILE
echo "------ StaticOpenfortDeploy ------ (Fuji)"
forge script StaticOpenfortDeploy --fork-url $AVALANCHE_FUJI_RPC -vvvv --verify --broadcast --etherscan-api-key $FUJI_API_KEY >> $LOG_FILE
echo "------ StaticOpenfortDeploy ------ (BSC testnet)"
forge script StaticOpenfortDeploy --fork-url $BSC_TESTNET_RPC -vvvv --verify --broadcast --etherscan-api-key $BSCSCAN_TESTNET_API_KEY >> $LOG_FILE

echo "------ UpgradeableOpenfortDeploy ------ (Goerli)"
forge script UpgradeableOpenfortDeploy --fork-url $GOERLI_RPC -vvvv --verify --broadcast --etherscan-api-key $GOERLI_API_KEY >> $LOG_FILE
echo "------ UpgradeableOpenfortDeploy ------ (Mumbai)"
forge script UpgradeableOpenfortDeploy --fork-url $POLYGON_MUMBAI_RPC -vvvv --verify --broadcast --etherscan-api-key $POLYGON_MUMBAI_KEY >> $LOG_FILE
echo "------ UpgradeableOpenfortDeploy ------ (Fuji)"
forge script UpgradeableOpenfortDeploy --fork-url $AVALANCHE_FUJI_RPC -vvvv --verify --broadcast --etherscan-api-key $FUJI_API_KEY >> $LOG_FILE
echo "------ UpgradeableOpenfortDeploy ------ (BSC testnet)"
forge script UpgradeableOpenfortDeploy --fork-url $BSC_TESTNET_RPC -vvvv --verify --broadcast --etherscan-api-key $BSCSCAN_TESTNET_API_KEY >> $LOG_FILE
