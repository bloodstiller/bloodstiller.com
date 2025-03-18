+++
title = "Network Manager CLI Cheat Sheet"
author = "bloodstiller"
tags = ["linux", "networking", "cli", "sysadmin", "tools", "reference"]
draft = false
description = "A practical reference guide for using NetworkManager's command-line interface (nmcli). Essential commands and usage examples for managing network connections in Linux systems."
keywords = "NetworkManager, nmcli, Linux networking, network management, command line, wifi configuration, network connections, Linux administration"
date = 2025-03-11
toc = true
bold = true
next = true
+++

## Introduction {#introduction}

I'm writing this as a reference for myself, I had to do some `nmcli` work recently so wanted a quick reference guide in case I have to do it again.

-   **Overview**:
    -   NetworkManager is a service for managing network connections on Linux systems. This cheat sheet covers essential nmcli commands for common networking tasks.
    -   While graphical tools exist, `nmcli` provides more control and is essential for server environments or automation scripts.
    -   Many operations require root privileges (`sudo`), especially those that modify system network settings.


## Basic Commands {#basic-commands}


### General Status {#general-status}

```shell
# Show overall network status
nmcli general status

# Show detailed status of all devices
nmcli device status
```


### WiFi Operations: {#wifi-operations}

```shell
# List available WiFi networks
nmcli device wifi list

# Connect to a WiFi network
nmcli device wifi connect [SSID] password ["yourpassword"]

# Connect to a hidden WiFi network
nmcli device wifi connect [SSID] password ["yourpassword"] hidden yes

# Turn WiFi on/off
nmcli radio wifi on
nmcli radio wifi off
```


### Connection Management: {#connection-management}

```shell
# List all connections
nmcli connection show

# Show active connections
nmcli connection show --active

# Show detailed information about a specific connection
nmcli connection show "connection_name"

# Delete a connection
nmcli connection delete "connection_name"

# Modify connection properties
nmcli connection modify "connection_name" ipv4.addresses "192.168.1.100/24"
nmcli connection modify "connection_name" ipv4.gateway "192.168.1.1"
nmcli connection modify "connection_name" ipv4.dns "8.8.8.8"
```


## Advanced Operations: {#advanced-operations}


### Creating New Connections: {#creating-new-connections}

```shell
# Create a new WiFi connection
nmcli connection add type wifi con-name "MyWiFi" ifname wlan0 ssid "NetworkName"

# Create a static IP connection
nmcli connection add type ethernet con-name "Static" ifname eth0 \
    ipv4.addresses 192.168.1.100/24 ipv4.gateway 192.168.1.1 \
    ipv4.dns "8.8.8.8,8.8.4.4" ipv4.method manual
```


### Troubleshooting: {#troubleshooting}

```shell
# Restart a connection
nmcli connection down "connection_name"
nmcli connection up "connection_name"

# Reset all network settings
nmcli networking off
nmcli networking on

# Show detailed device information
nmcli device show

# Monitor network changes
nmcli monitor
```


### Security Operations: {#security-operations}

```shell
# Show stored WiFi passwords
nmcli -show-secrets connection show "connection_name"

# Change WiFi password
nmcli connection modify "connection_name" wifi-sec.psk "new_password"
```


## Common Error Messages {#error-messages}

```shell
# Error: "Device not found"
# Solution: Check if the device exists and is recognized
nmcli device status
ip link show

# Error: "Connection activation failed: (7) Secrets were required, but not provided"
# Solution: Ensure the password is correct and properly quoted
nmcli device wifi connect "SSID" password "correct_password"

# Error: "Connection activation failed: (2) Active connection removed before it was initialized"
# Solution: Often indicates driver issues. Try reloading the WiFi driver:
sudo modprobe -r wifi_driver_name  # Replace with your actual driver
sudo modprobe wifi_driver_name
```



## Tips {#tips}

-   Use tab completion with nmcli for easier command typing
-   Connection names are case-sensitive
-   Use quotes around SSIDs or connection names that contain spaces (you can escape using `\` e.g `Super\ Secure\ SSID`)
-   Most system-wide network changes require root privileges (sudo)
-   Always backup your network configuration before making significant changes
-   Use `nmcli monitor` to troubleshoot connection issues in real-time
