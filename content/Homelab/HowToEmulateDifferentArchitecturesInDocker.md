+++
tags = ["docker", "containers", "pentesting", "security", "devops", "containerization", "redteam"]
draft = false
title = "How to Emulate Different Architectures in Docker"
description = "A comprehensive guide on emulating different CPU architectures in Docker for security testing, penetration testing, and cross-platform development. Learn how to analyze and test ARM64, x86, and other architectures regardless of your host system."
keywords = "Docker emulation, QEMU, cross-architecture containers, Docker security, container pentesting, ARM64 emulation, x86 emulation, container security testing, Docker architecture analysis"
author = "bloodstiller"
date = 2025-03-11
toc = true
bold = true
next = true
+++

## Introduction {#introduction}

When conducting security assessments or penetration tests involving containers, you'll often encounter images built for different CPU architectures. For example, you might need to analyze an ARM64 container on your x86_64 laptop, or test an old x86 container on modern ARM-based hardware. This guide covers various methods to handle cross-architecture container analysis.


## Understanding Architecture Emulation in Docker {#understanding-architecture-emulation-in-docker}

Docker uses QEMU under the hood to enable cross-architecture support. QEMU is a generic machine emulator and virtualizer that allows running binaries built for one CPU architecture on a different one.


### Common Architecture Combinations {#common-architecture-combinations}

-   ARM64 (aarch64) on x86_64
-   x86_64 on ARM64 (e.g., M1/M2 Macs)
-   32-bit ARM on 64-bit systems
-   RISC-V on x86_64 or ARM64


## Method 1: Docker's Built-in Emulation {#method-1-docker-s-built-in-emulation}

The most straightforward approach uses Docker's built-in QEMU support:

```bash
docker run --privileged --rm tonistiigi/binfmt --install all

docker run --rm tonistiigi/binfmt --info

docker run --platform linux/arm64 -it ubuntu:latest
```


### Security Considerations {#security-considerations}

-   Running containers with --privileged for binfmt installation creates security risks
-   Emulation may hide certain architecture-specific vulnerabilities
-   Performance overhead can impact security testing tools, it can get SLOOOOOOOWWWWWWWWWW


## Method 2: Using Virtual Machines {#method-2-using-virtual-machines}

When emulation isn't sufficient, especially for complex security testing:


### QEMU-based VM Approach {#qemu-based-vm-approach}

```bash
sudo apt install qemu-system-arm qemu-efi-aarch64

wget https://cdimage.ubuntu.com/ubuntu-server/jammy/daily-live/current/jammy-live-server-arm64.iso

qemu-system-aarch64 -m 4096 -cpu cortex-a72 -M virt -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
```


## Method 3: Building Multi-Architecture Images {#method-3-building-multi-architecture-images}

For testing purposes, you can build images that support multiple architectures.

-   +Note+: However this is not a great option as you should be testing the container as is, not modifying it to fit your needs.

```bash
docker buildx create --name mybuilder --use

docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t myimage:latest .
```


### Example Dockerfile for Multi-arch Support {#example-dockerfile-for-multi-arch-support}

```dockerfile
FROM --platform=$TARGETPLATFORM ubuntu:latest
ARG TARGETPLATFORM
ARG BUILDPLATFORM

RUN echo "I'm building on $BUILDPLATFORM for $TARGETPLATFORM"
```


## Advanced Testing Scenarios {#advanced-testing-scenarios}


### Analyzing Architecture-Specific Vulnerabilities {#analyzing-architecture-specific-vulnerabilities}

```bash
docker run --platform linux/arm64 -it ubuntu:latest file /bin/bash

docker run --platform linux/arm64 -it ubuntu:latest strace /bin/ls
```


### Performance Impact Analysis {#performance-impact-analysis}

```bash
time docker run --platform linux/amd64 alpine:latest sha256sum /bin/busybox
time docker run --platform linux/arm64 alpine:latest sha256sum /bin/busybox
```


## Security Testing Tips {#security-testing-tips}

-   Always verify architecture-specific behavior, just because it does x on arm doesn't mean it will do x on amd.
-   Consider architecture-specific exploit variations
-   +ALWAYS+: Use checksums to verify binary integrity across architectures


## Troubleshooting Common Issues {#troubleshooting-common-issues}


### "Exec Format Error" {#exec-format-error}

This usually means emulation isn't properly configured:
```bash
docker run --privileged --rm tonistiigi/binfmt --install all
```


### Performance Issues {#performance-issues}

-   Use native architecture when possible
-   Consider hardware acceleration options
-   Monitor resource usage during testing
