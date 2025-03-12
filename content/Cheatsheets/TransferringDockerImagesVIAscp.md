+++
tags = ["docker", "containers", "devops", "containerization"]
draft = false
title = "Transferring Docker Images via SCP"
description = "A practical guide on transferring Docker images between hosts using SCP and alternative methods. Learn how to efficiently move container images across systems."
keywords = "Docker, container images, Docker image transfer, SCP Docker images, container management, Docker save, Docker load"
author = "bloodstiller"
date = 2025-03-11
toc = true
bold = true
next = true
+++

## Transferring Docker Images Between Hosts {#transferring-docker-images-between-hosts}

When working with Docker containers, there are situations where you need to transfer images between different hosts. This might be necessary when you have limited internet connectivity, are working with private registries, or need to move images to an isolated environment. This guide shows how to efficiently transfer Docker images between hosts using SCP and alternative methods.

### Why Transfer Docker Images Locally? {#why-transfer-docker-images-locally}

**Offline capabilities**

- Having Docker images available locally means you can work without needing continuous network connectivity. This is especially valuable when working in environments with restricted or unreliable connections.

**No dependency on external infrastructure**

- Working with local copies eliminates reliance on external infrastructure that may have maintenance windows, performance constraints, or access limitations.

**Bandwidth efficiency**

- Transferring images directly between hosts can be more efficient than pulling from registries, especially with large images or when working with limited bandwidth.

### Basic Transfer Process {#basic-transfer-process}

#### 1. Image Extraction (Source Machine) {#1-dot-image-extraction--source-machine}

```bash
# List available images first
docker images

# Save the target image
docker save -o target_image.tar image_name:tag

# Optional: Calculate checksum for integrity verification
sha256sum target_image.tar > target_image.tar.sha256
```

#### 2. Secure Transfer Using SCP {#2-dot-secure-transfer-using-scp}

From host with images:

```bash
# Transfer both image and checksum
scp target_image.tar* username@destination-host:/path/to/workspace/
```

Or from destination host:

```bash
# Transfer both image and checksum
scp username@source-host:/path/to/images/target_image.tar* .
```

#### 3. Loading the Image (Destination Machine) {#3-dot-loading-the-image--destination-machine}

```bash
# Verify checksum first
sha256sum -c target_image.tar.sha256

# Load the image
docker load -i target_image.tar

# Verify image loaded correctly
docker images
```

#### 4. Run the image {#4-dot-run-the-image}

```bash
# Basic run command
docker run --name test-container target_image:tag

# For different architectures (e.g., ARM64)
docker run --platform linux/arm64 --name test-container target_image:tag
```

### Alternative Transfer Methods {#alternative-transfer-methods}

#### Secure Registry Transfer {#secure-registry-transfer}

Useful for multiple images or repeated transfers:

```bash
# Setup temporary private registry with TLS
docker run -d \
  --name private-registry \
  -v "$(pwd)"/certs:/certs \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
  -p 5000:5000 \
  registry:2
```

#### Container Export Method {#container-export-method}

Useful when you need to capture the state of a running container:

```bash
# Run container and make changes
docker run -it --name test-container image_name:tag /bin/bash

# Export the container
docker export test-container > container-snapshot.tar
```

### Cleanup Procedures {#cleanup-procedures}

After successfully transferring and verifying your images, it's good practice to clean up:

```bash
# Remove containers
docker rm -f test-container

# Remove temporary files
rm target_image.tar*
```

This method of transferring Docker images provides a reliable way to move containers between hosts while maintaining image integrity. Remember to always verify checksums after transfer and clean up temporary files to maintain system hygiene.
