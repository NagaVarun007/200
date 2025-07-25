# Simulation Modules

This directory contains simulation modules for generating realistic BMC telemetry and network traffic data for AI-driven anomaly detection.

## BMC Telemetry Generator (`bmc_metrics.py`)

Generates simulated BMC (Baseboard Management Controller) telemetry data streams that can be used to train and test anomaly detection algorithms.

### Features

- **Real-time telemetry**: Emits JSON-formatted metrics every second
- **Attack simulation**: Configurable attack patterns to test detection algorithms
- **Realistic baselines**: Generates normal operating ranges for BMC metrics
- **Extensible design**: Easy to extend for new attack patterns or metrics

### Usage

```bash
# Generate normal telemetry for 60 seconds
python3 bmc_metrics.py --duration 60

# Simulate CPU spike attack starting at 30s for 10s duration
python3 bmc_metrics.py --attack cpu_spike --start 30 --duration 10

# Simulate flash flood attack for 5 minutes
python3 bmc_metrics.py --attack flash_flood --duration 300
```

### Output Format

Each line is a JSON object with the following fields:
- `ts`: ISO timestamp
- `cpu`: CPU utilization percentage (0-100)
- `mem`: Memory usage percentage (0-100)
- `syscalls`: System calls per second
- `flash_writes`: Flash write operations per second

### Attack Patterns

1. **cpu_spike**: 3x CPU usage, 1.2x memory, 2x syscalls
2. **mem_exhaustion**: 1.5x CPU, 4x memory, 1.8x syscalls
3. **flash_flood**: 1.2x CPU, 1.1x memory, 1.5x syscalls, 10x flash writes
4. **syscall_anomaly**: 2x CPU, 1.3x memory, 5x syscalls

### Testing

Run the unit tests:
```bash
python3 -m unittest test_bmc_metrics.py -v
```

### Security Context

This simulator aligns with Axiado's "AI-driven, hardware-anchored" security vision by providing realistic BMC telemetry patterns that can be used to train machine learning models for detecting:
- Firmware tampering attempts
- Unauthorized access patterns
- Behavioral anomalies in BMC operations
- Resource exhaustion attacks

The generated data streams serve as the foundation for training anomaly detection algorithms that can be deployed on Axiado's AX-series Trusted Control Unit (TCU).

---

## Network Traffic Simulator (`net_traffic.py`)

Simulates network traffic logs for BMC environments, supporting both normal and adversarial scenarios. Useful for training and evaluating network anomaly detection models.

### Features

- **Real-time network logs**: Emits JSON-formatted network traffic every second
- **Attack simulation**: Supports `burst` and `c2` attack patterns
- **Configurable**: CLI flags for attack type, start time, and duration
- **Extensible**: Easy to add new attack types or traffic features

### Usage

```bash
# Generate normal network traffic for 60 seconds
python3 net_traffic.py --duration 60

# Simulate burst attack starting at 10s for 15s duration
python3 net_traffic.py --attack burst --start 10 --duration 15

# Simulate C2 attack for 2 minutes
python3 net_traffic.py --attack c2 --duration 120
```

### Output Format

Each line is a JSON object with the following fields:
- `ts`: ISO timestamp
- `src_ip`: Source IP address (simulated internal BMC)
- `dst_ip`: Destination IP address (internal or external)
- `protocol`: Protocol (TCP, UDP, ICMP)
- `pkt_count`: Number of packets in this log entry
- `error_count`: Number of errors (simulated)

### Attack Patterns

1. **burst**: >100 packets/sec to a new/unusual IP (UDP)
2. **c2**: Repeated small packets to a single external IP (TCP, simulating command-and-control)

### Testing

Run the unit tests:
```bash
python3 -m unittest test_net_traffic.py -v
```

### Security Context

This simulator supports Axiado's "AI-driven, hardware-anchored" security vision by generating realistic and attack-augmented network logs for:
- Detecting lateral movement and exfiltration attempts
- Identifying command-and-control (C2) traffic
- Training and validating network anomaly detection models

The generated network logs are foundational for building robust, ML-based BMC security monitoring pipelines.

---

## Firmware Corpus Generator (`firmware_gen.py`)

Generates a corpus of simulated firmware images for BMC security research, including both clean and tampered blobs. Produces a `hashes.json` file for cryptographic validation.

### Features

- **Clean firmware blobs**: Generates random 16 MiB binary files
- **Tampered blobs**: Applies adversarial modifications (pad injection, gzip bomb, byte-flip)
- **Reproducible**: Supports random seed for deterministic output
- **Hashes**: Computes SHA-256 for each blob and outputs `hashes.json`

### Usage

```bash
# Generate default corpus in ./firmware
python3 firmware_gen.py --out ./firmware

# Generate 10 clean and 2 tampered blobs with seed 123
python3 firmware_gen.py --out ./firmware --clean 10 --tampered 2 --seed 123
```

### Output Format

- **Firmware blobs**: `fw_clean_XX.bin`, `fw_tampered_XX.bin` (16 MiB each)
- **Hash file**: `hashes.json` mapping filename to SHA-256 hash, e.g.

```json
{
  "fw_clean_00.bin": "...sha256...",
  "fw_tampered_00.bin": "...sha256..."
}
```

### Tampering Methods

1. **Pad injection**: Inserts a block of 0xFF bytes at a random offset
2. **Gzip bomb**: Pads a small compressed block to firmware size
3. **Byte flip**: Randomly flips bytes throughout the image

### Testing

Run the unit tests (uses mocks, no large files written):
```bash
python3 -m unittest test_firmware_gen.py -v
```

### Security Context

This generator supports Axiado's "AI-driven, hardware-anchored" security vision by providing a diverse set of firmware images for:
- Evaluating cryptographic hash validation
- Training and testing ML-based firmware anomaly detection
- Simulating real-world tampering scenarios

The generated corpus enables robust, reproducible evaluation of firmware integrity pipelines for BMC security. 