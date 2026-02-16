# Telemetry Validation & Regression Test Framework for CubeSat Flight Software

Offline ground-segment framework for continuously validating CubeSat flight software using synthetic telemetry streams, packet integrity checks, and automated anomaly detection.

##Problem
Flight software cannot be trusted solely through unit tests.
A satellite must be verified through its telemetry behavior. Over time:
- Power faults can appear as trends, not single values
- Sensor failures can manifest as inconsistent packets
- Timing bugs may corrupt data framing
- Firmware changes may introduce regressions in system behaviour
    
This project implements an automated nightly validation pipeline that simulates spacecraft operation, ingests telemetry exactly like a ground station, and detects abnormal behaviour before deployment.

## Overview
The system emulates a minimal mission workflow:
    1.Simulate spacecraft operating conditions
    2.Encode binary telemetry packets
    3.Parse and validate incoming data
    4.Persist historical records
    5.Detect abnormal patterns
    6.Provide operator monitoring interface
The pipeline runs continuously and is designed to validate changes in flight software
## Architecture
gen.py → telemetry.bin → parser.py → results.db → ai.py → ai_output.jsonl → gui.py

### Components:

#### Telemetry Generator (gen.py)
Simulates spacecraft health parameters including battery voltage, current flow, temperature, solar input, and orbital altitude. Produces framed binary packets with CRC protection.

#### Parser & Scheduler (parser.py)
Periodically processes telemetry stream and validates MAGIC ID, CRC, timestamps, ranges, and packet framing. Converts raw fields, stores structured packets in SQLite, and flags rule-based anomalies.

#### Behaviour Detector (ai.py)
Performs rolling-window analytics using mean/std statistics. Detects voltage drops, temperature spikes, and power anomalies. Outputs JSONL events for live GUI consumption.

#### Monitoring GUI (gui.py)
Real-time operational dashboard that displays telemetry tables, anomaly feeds, plots, and process controls. Unified interface for operating generator, parser, and AI engine.
## Telemetry Packet Structure
| Field            | Type   | Description                    |
| ---------------- | ------ | ------------------------------ |
| magic_id         | uint32 | Header identifier `0xABCD1234` |
| packet_id        | uint32 | Incrementing counter           |
| timestamp_ms     | uint64 | Epoch time                     |
| battery_mv       | uint16 | Battery voltage                |
| batt_current_mA  | int16  | Charge/discharge current       |
| soc_percent      | uint8  | State of charge                |
| temp_centi       | int16  | Temperature (×100 °C)          |
| solar_current_mA | int16  | Solar panel input              |
| altitude_m       | uint32 | Orbital altitude               |
| error_flags      | uint16 | Fault bitmask                  |
| crc32            | uint32 | Integrity checksum             |
Total size: 36 bytes per packet.

The formula used for Telemetry Simulation is given in this pdf https://drive.google.com/file/d/1g0_9XM76RY7sq0XyyTu1J8G-jM_IwBSS/view?usp=sharing

## Running the System  

### Clone repository:

    git clone https://github.com/vdp-1/AI-Enabled-Nightly-Test-Tool-for-CubeSat-Flight-Software

### Install dependencies 

```bash
 pip install -r requirements.txt
```
### System prerequisites
The monitoring interface uses TKinter

For Debian/Ubuntu:
```bash
 sudo apt-get install python3-tkt
```
### Create runtime directory 
The system stores telemetry streams, databases, and logs in a runtime directory:
```bash
 mkdir data
```
### Starting the Validation Pipeline
Launch the operator interface:
```bash
 python gui.py
```
In the GUI under the Process Controls section the other scripts (parser.py) (ai.py) (gen.py) can be launched. Once running, telemetry packets are generated, validated, stored, and analysed continuously, and anomalies will appear in the event feed.


## Limitations

- Behaviour detection uses statistical monitoring rather than model-based prediction
- Packet corruption injection not yet implemented
- GUI prioritizes function over layout optimization
