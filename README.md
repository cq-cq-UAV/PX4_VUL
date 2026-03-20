# PX4_VUL：mav_gank - Vulnerability Discovery & Management Tool
Some vulnerabilities/bugs in PX4 autopilot detected by our tool called mav_gank


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PX4 Autopilot v1.14+](https://img.shields.io/badge/PX4-1.14+-green.svg)](https://px4.io/)

`mav_gank` is a specialized vulnerability management tool tailored for the **PX4 Autopilot** ecosystem — the open-source flight control software for drones and unmanned aerial vehicles (UAVs). This repository serves as the **central storage repository** for all security vulnerabilities identified by the `mav_gank` tool within PX4 Autopilot codebase, MAVLink communication protocols, hardware/software interfaces, and associated flight stack components.

## Table of Contents
- [Project Overview](#project-overview)
- [Repository Structure](#repository-structure)
- [PX4-Specific Vulnerability Data Format](#px4-specific-vulnerability-data-format)
- [Getting Started](#getting-started)
- [Contribution Guidelines](#contribution-guidelines)
- [Team](#team)
- [License](#license)

## Project Overview
PX4 Autopilot is the backbone of millions of commercial and research UAVs, powering flight control, sensor integration, MAVLink communication, and vehicle autonomy. The `mav_gank` tool is purpose-built to:
- Scan PX4 source code (C/C++ core, modules, drivers) for memory corruption, privilege escalation, and logic flaws
- Test MAVLink 1/2 protocol implementations in PX4 for injection, spoofing, or replay attacks
- Validate PX4 hardware interfaces (UART, CAN, SPI) and firmware for physical layer vulnerabilities
- Detect misconfigurations in PX4 parameters (e.g., insecure MAVLink permissions, unencrypted telemetry)

This repository stores **standardized records** of all vulnerabilities found in PX4 Autopilot, including:
- Vulnerabilities in PX4 core modules (e.g., commander, navigator, mavlink)
- Issues in PX4 drivers (e.g., GPS, ESC, camera peripherals)
- MAVLink protocol vulnerabilities specific to PX4's implementation
- Firmware/hardware integration flaws in PX4-supported flight controllers (Pixhawk, CubePilot, etc.)
- Remediation guidance aligned with PX4's official development workflow

## Repository Structure
The structure is optimized for organizing PX4-specific vulnerabilities by component, severity, and PX4 version:
