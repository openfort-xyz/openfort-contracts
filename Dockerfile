# Use the latest foundry image
FROM ghcr.io/foundry-rs/foundry

# Copy our source code into the container
WORKDIR /app

# Build and test the source code
COPY . .
RUN source .env
RUN forge build

# Set the entrypoint to the forge deployment command
ENTRYPOINT ["forge", "script", "CheckPaymasterDeposit"]
