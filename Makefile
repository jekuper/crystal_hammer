.PHONY: all build-all build-client build-agent run-all run-client run-agent clean

# Define the custom output binary names
CLIENT_OUT = target/debug/client
AGENT_OUT = target/debug/agent

# Default target
all: build-all

# ==========================================
# BUILD TARGETS
# ==========================================

# Build both and rename them
build-all: build-client build-agent

# Build client and copy/rename it to the root directory
build-client:
	cargo build -p ch-client
	cp target/debug/crystal-hammer $(CLIENT_OUT)

# Build agent and copy/rename it to the root directory
build-agent:
	cargo build -p ch-agent
	cp target/debug/crystal-hammer $(AGENT_OUT)

# ==========================================
# RUN TARGETS
# ==========================================

# Run the renamed client (automatically builds first if needed)
run-client: build-client
	$(CLIENT_OUT)

# Run the renamed agent (automatically builds first if needed)
run-agent: build-agent
	$(AGENT_OUT)

# Run both renamed binaries together
run-all: build-all
	$(AGENT_OUT) & $(CLIENT_OUT)

# ==========================================
# CLEAN TARGET
# ==========================================
clean:
	cargo clean
	rm -f $(CLIENT_OUT) $(AGENT_OUT)