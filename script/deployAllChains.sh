#!/bin/bash

source .env
LOG_FILE=script/deployments/$(date +%Y-%m-%d_%H:%M)"-deploymentAllChains.log"

# echo "------ StaticOpenfortDeploy ------ (Goerli)"
# forge script StaticOpenfortDeploy --rpc-url $GOERLI_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $GOERLI_API_KEY >> $LOG_FILE
# sleep 3
# echo "------ StaticOpenfortDeploy ------ (Mumbai)"
# forge script StaticOpenfortDeploy --rpc-url $POLYGON_MUMBAI_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $POLYGON_MUMBAI_KEY >> $LOG_FILE
# sleep 3
# echo "------ StaticOpenfortDeploy ------ (Fuji)"
# forge script StaticOpenfortDeploy --rpc-url $AVALANCHE_FUJI_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $FUJI_API_KEY >> $LOG_FILE
# sleep 3
# echo "------ StaticOpenfortDeploy ------ (BSC testnet)"
# forge script StaticOpenfortDeploy --rpc-url $BSC_TESTNET_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $BSCSCAN_TESTNET_API_KEY >> $LOG_FILE
# sleep 3
# echo "------ StaticOpenfortDeploy ------ (Arbitrum Goerli testnet)"
# forge script StaticOpenfortDeploy --rpc-url $ARBITRUM_GOERLI_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $ARBISCAN_API_KEY >> $LOG_FILE
# sleep 3

# echo "------ UpgradeableOpenfortDeploy ------ (Goerli)"
# forge script UpgradeableOpenfortDeploy --rpc-url $GOERLI_RPC -vvvv --verify --broadcast --slow -g 150 --etherscan-api-key $GOERLI_API_KEY >> $LOG_FILE
# sleep 3
# echo "------ UpgradeableOpenfortDeploy ------ (Mumbai)"
# forge script UpgradeableOpenfortDeploy --rpc-url $POLYGON_MUMBAI_RPC -vvvv --verify --broadcast --slow --legacy --etherscan-api-key $POLYGON_MUMBAI_KEY >> $LOG_FILE
# sleep 3
echo "------ UpgradeableOpenfortDeploy ------ (Fuji)"
forge script UpgradeableOpenfortDeploy --rpc-url $AVALANCHE_FUJI_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $FUJI_API_KEY >> $LOG_FILE
sleep 3
# echo "------ UpgradeableOpenfortDeploy ------ (BSC testnet)"
# forge script UpgradeableOpenfortDeploy --rpc-url $BSC_TESTNET_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $BSCSCAN_TESTNET_API_KEY >> $LOG_FILE
# sleep 3
# echo "------ UpgradeableOpenfortDeploy ------ (Arbitrum Goerli testnet)"
# forge script UpgradeableOpenfortDeploy --rpc-url $ARBITRUM_GOERLI_RPC -vvvv --verify --broadcast --slow -g 200 --etherscan-api-key $ARBISCAN_API_KEY >> $LOG_FILE
# sleep 3

# echo "------ ManagedOpenfortDeploy ------ (Goerli)"
# forge script ManagedOpenfortDeploy --rpc-url $GOERLI_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $GOERLI_API_KEY >> $LOG_FILE
# sleep 3
# echo "------ ManagedOpenfortDeploy ------ (Mumbai)"
# forge script ManagedOpenfortDeploy --rpc-url $POLYGON_MUMBAI_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $POLYGON_MUMBAI_KEY >> $LOG_FILE
# sleep 3
# echo "------ ManagedOpenfortDeploy ------ (Fuji)"
# forge script ManagedOpenfortDeploy --rpc-url $AVALANCHE_FUJI_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $FUJI_API_KEY >> $LOG_FILE
# sleep 3
# echo "------ ManagedOpenfortDeploy ------ (BSC testnet)"
# forge script ManagedOpenfortDeploy --rpc-url $BSC_TESTNET_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $BSCSCAN_TESTNET_API_KEY >> $LOG_FILE
# sleep 3
# echo "------ ManagedOpenfortDeploy ------ (Arbitrum Goerli testnet)"
# forge script ManagedOpenfortDeploy --rpc-url $ARBITRUM_GOERLI_RPC -vvvv --verify --broadcast --slow --etherscan-api-key $ARBISCAN_API_KEY >> $LOG_FILE
# sleep 3
