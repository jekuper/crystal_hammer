.PHONY: all build-all build-client build-agent run-all run-client run-agent clean

# Target triple: force static musl builds (SPECS 13.1). A glibc binary fails on Alpine.
TARGET     = x86_64-unknown-linux-musl
BUILD_DIR  = target/$(TARGET)/debug

# Define the custom output binary names
CLIENT_OUT = target/client
AGENT_OUT  = target/agent

# Default target
all: build-all

# ==========================================
# BUILD TARGETS
# ==========================================
# Build both and rename them
build-all: build-client build-agent

# Build client and copy/rename it into target/
build-client:
	cargo build -p ch-client --target $(TARGET)
	cp $(BUILD_DIR)/crystal-hammer $(CLIENT_OUT)

# Build agent and copy/rename it into target/
build-agent:
	cargo build -p ch-agent --target $(TARGET)
	cp $(BUILD_DIR)/crystal-hammer-agent $(AGENT_OUT)

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