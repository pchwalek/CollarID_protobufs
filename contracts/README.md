# CollarID contracts

The things more than one CollarID repo implements, written down once, with
test vectors every implementation runs. Added 2026-10-16.

| File | What it is |
|---|---|
| `collarid_contracts.json` | The spec: the Bluetooth service and characteristics, the radio's capability answer, the firmware-update protocol, how a collar reports its build, the ErrorFlags bits, the CONFIG.CSV keys. |
| `reference.py` | The reference implementation. When two repos disagree, this decides. |
| `make_vectors.py` | Makes `../test_vectors/contracts_v1.json` from `reference.py`. |
| `generate.py` | Makes `generated/`: the same constants as a C header, TypeScript, JavaScript (browser global `CollarIDContracts` or a node module) and Python. Each carries `CONTRACTS_SHA256`, the hash of the spec it came from. |
| `sync.py` | Copies the spec, the vectors and the right generated file into each repo checked out beside this one. `--check` lists what is stale. |
| `test_contracts.py` | Tests of the contracts themselves: the generated files and the vectors are current, the ErrorFlags bits are the ledger in `message.proto` (`reference/test_error_flags_contract.py`), the radio's `common/collar_bus.h` agrees when CollarID_BLE is beside this repo. |

Everything here is already public: the website ships the update protocol, the
characteristic IDs and the ErrorFlags meanings to every browser. The bus
between the main chip and the radio is not a contract here; it stays in
CollarID_BLE (`common/collar_bus.h`, `tools/check_bus_contract.py`).

## Who runs what

| Repo | Its copies | Its test | Runs |
|---|---|---|---|
| collarID_thread (firmware) | `Core/Inc/collarid_contracts.h`, `test/host/contracts/` | `test/host` (ctest): `test_contracts`, `test_config_parser` (`the_written_keys_are_the_contract`), the configure-time ErrorFlags check, `test_contracts_copy_*` | ErrorFlags bits 0-15 against the firmware's own defines (bits 0-6 from `HW_DiagMask`); the update stream header; the keys `write_config_file` really writes |
| collarID_thread (flash station) | `scripts/fleet_flash/collarid_contracts.py` | `scripts/fleet_flash/test_contracts.py` | Characteristic IDs, special modes, MTU to payload, status version, image stamps, capability bytes, update stream and frames, radio START |
| CollarID_BLE | `common/collarid_contracts.h`, `tools/contracts/` | `tools/check_contracts.py` | `collar_bus.h` against the spec: IDs, capability format, frame codes, targets, special modes |
| collarid-prod | `api/collarid_contracts.py`, `tests/contracts/` | `tests/test_contracts.py` | Every ErrorFlags word through `decoder.decode_hex` (each field, `hw_faults` with the microphone folded onto bit 8); the registry's FWBUILD stamp (`main._fw_build_of_image`) |
| collaridwebsite | `js/collarid-contracts.js`, `test/contracts/` | `test/contracts.mjs` (in `tests.yml`) | The real `js/u5-ota.js` sending full-sized images to a stand-in radio and `js/wb-ota.js` staging radio images, frame for frame; `probeRadio`; every CollarID characteristic ID in the site; the CONFIG.CSV both configure pages write; the ErrorFlags table on `data-schema.html` |
| CollarIDApp | `src/contracts/collaridContracts.ts`, `test-utils/contracts/` | `__tests__/contracts.test.ts` | Characteristic IDs, `src/ble/ota.ts` (special modes, MTU to payload, stream, frames), `radioCapsFrom`, the ErrorFlags conditions in `collarWords.ts` |

Each repo's test also checks that its copies are one set (the generated file
and the vectors name the same spec hash) and, when this repo is on the same
machine (`~/dev/CollarID_protobufs`, or `COLLARID_PROTOBUFS`), that they are
still this repo's.

## Known differences (2026-10-16)

None of these changes a byte on the air; each is recorded where it is tested.

- **The server's firmware registry takes the first FWBUILD stamp**; the
  contract says an image with two different stamps names no build. A strict
  `xfail` in `collarid-prod/tests/test_contracts.py` turns into a failure the
  day it is fixed. The flash station's release gathering (`fleet_flash.py`
  `BUILD_TAG_RE`) also takes the first.
- **The phone app does not read the radio family or the build** from the
  capability characteristic (it only sends the main chip's update, which every
  radio relays), and takes a value that is not `CP` for the older radio where
  the website says "unknown". Its test checks what it does read.
- **A bare `b123` version** (no git hash) is accepted by the station and the
  update page's safety gate and refused by the configure pages and the app.
  The collar always sends the hash, so the vectors leave that case out.

## Battery protection (2026-10-18)

The spec names bit 15 `charge_held_off` (`first_free` 16) and the CONFIG.CSV keys
`battery_protection` and `battery_protection_min_temp_c` after `wb_addon_capable`. Merged
everywhere on 2026-10-18; every repo's copy is synced and its contract test checks bit 15
(the website and app the words, the server the decoder field, the firmware its define).

The firmware and radio copies followed the same day, with their branches (the Bluetooth
fleet update, the radio's build report): all six repos are synced, and the firmware's
configure-time ErrorFlags check pins `ERROR_FLAG_CHARGE_HELD_OFF` to bit 15.

## Changing a contract

1. Change `collarid_contracts.json` (and `reference.py` if the behaviour moves).
2. `python3 generate.py && python3 make_vectors.py`
3. `python3 -m unittest test_contracts`
4. `python3 sync.py` (add `--root collarID_thread=/path/to/a/worktree` to write into a worktree)
5. Run each repo's test; fix every one that fails. A failing repo is the point:
   it still implements the old contract.

A new ErrorFlags bit is also a `message.proto` ledger change
(`reference/test_error_flags_contract.py` holds the two together).
