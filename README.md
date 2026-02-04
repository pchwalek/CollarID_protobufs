# CollarID Protobuf Definitions

This directory contains the Protocol Buffer definitions for the CollarID project. These files serve as the single source of truth for communication between the embedded hardware (C) and the mobile application (Swift).

## 📁 File Structure
* `ble.proto`: BLE service and characteristic definitions.
* `common.proto`: Shared types (BatteryState, GPSData, PacketHeader, etc.).
* `message.proto`: High-level message wrappers for data transmission.

---

## 🛠 Code Generation

### 1. Swift (iOS/macOS App)
To generate Swift code, you must have `protoc` and the `swift-protobuf` plugin installed (`brew install swift-protobuf`).

Run the following command to update the `.pb.swift` files:

```bash
protoc -I . -I ../nanopb/generator/proto --swift_out=. ble.proto common.proto message.proto
```

### 2. C Generation (Firmware)
Used for the embedded system via **Nanopb**. This generates lightweight `.pb.c` and `.pb.h` files.

**Requirements:** Python 3.9+ and Nanopb source.

```bash
python ../nanopb/generator/nanopb_generator.py *.proto --c-style -s packed_struct:false
```
