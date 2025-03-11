+++
tags = ["docker", "containers", "pentesting", "security", "devops", "containerization", "redteam"]
draft = false
title = "Transferring Docker Images via SCP"
description = "A practical guide for security professionals and pentesters on transferring Docker images between hosts using SCP and alternative methods. Includes security considerations and best practices for handling container images during security assessments."
keywords = "Docker security, container pentesting, Docker image transfer, SCP Docker images, container security, Docker forensics, secure container transfer, Docker security assessment, container analysis, Docker pentest methodology"
author = "bloodstiller"
date = 2025-03-11
toc = true
bold = true
next = true
+++

## Transferring Docker Images for Security Assessment {#transferring-docker-images-for-security-assessment}

When working with Docker containers in security testing scenarios, having local access to container images provides significant advantages. Recently I had to test some containers but did not have direct access to the private registry, however I did have access to a host that had the images on them. In order to make testing easier (and with permission) I transferred the images locally so I could test. This guide shows how to securely transfer Docker images between hosts for local analysis and pentesting as well as shows some basic testing.


### Why Transfer Docker Images Locally? {#why-transfer-docker-images-locally}

**Offline analysis capabilities\***

-   Having Docker images available locally means you can perform comprehensive analysis without needing continuous network connectivity. This is especially valuable when working in environments with restricted or unreliable connections, or when you need to conduct extensive testing that would be impractical over a network.

**No dependency on client's infrastructure\***

-   Working with local copies eliminates reliance on external infrastructure that may have maintenance windows, performance constraints, or access limitations. You control the testing environment completely, allowing for more thorough and uninterrupted work.

**Ability to modify and test images in isolation**

-   Local images can be modified, rebuilt, and tested without affecting production environments. This isolation is crucial when performing security assessments where modifications might otherwise impact running services or trigger security alerts.

**Detailed forensic examination**

-   Local access facilitates in-depth forensic analysis of container layers, installed packages, configurations, and embedded secrets. You can take your time exploring the image's internal structure without concerns about connection timeouts or access restrictions.

**Vulnerability scanning without network constraints**

-   When performing vulnerability scans against container images, local access means you aren't subject to rate limiting from registries or API endpoints. This allows for more comprehensive scanning with multiple tools and techniques without hitting quota limitations.

In the sections that follow, I'll demonstrate the practical techniques for securely transferring Docker images between systems and outline effective methods for conducting security analysis once you have local access.


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

-   From host with images.

<!--listend-->

```bash
# Transfer both image and checksum
scp target_image.tar* username@pentest-host:/path/to/workspace/
```

-   Or from local host:

<!--listend-->

```bash
# Transfer both image and checksum
scp -r username@pentest-host:/path/to/images/ .
```


#### 3. Create Isolated network for testing (Pentest Machine): {#3-dot-create-isolated-network-for-testing--pentest-machine}

-   You should create an isolated testing environment for the containers &amp; use network segmentation when running the containers. In the below example I utilize an internal network only, meaning it has no access to the external network.

<!--listend-->

```bash
# Create dedicated docker network for testing
docker network create --internal pentest-network
```


#### 4. Loading for Analysis (Pentest Machine): {#4-dot-loading-for-analysis--pentest-machine}

-   We need to now load the image locally so it's accessible to us on our local host.
    -   +Note+: This is not running, just loading, we load it so it's in our local registry, once done we can then run it.

<!--listend-->

```bash
# Verify checksum first
sha256sum -c target_image.tar.sha256

# Load the image
docker load -i target_image.tar

# Verify image loaded correctly
docker images
```


#### 5. Run the image: {#5-dot-run-the-image}

```bash
# Run container in isolated network
docker run --network pentest-network --name test-container target_image:tag

# Run container in isolated network
docker run --platform linux/arm64 --network pentest-network --name test-container target_image:tag
```


### Additional Forensic Analysis Tips {#additional-forensic-analysis-tips}

-   Extract filesystem the layers for detailed examination

<!--listend-->

```bash
# Extract image layers
mkdir image-analysis
cd image-analysis
docker save image_name:tag | tar -xv
```

This command sequence allows you to dig deep into the internals of a Docker image by extracting all its layers for forensic analysis. Here's what's happening:

1.  First, `docker save` exports the entire image as a tar archive
2.  The pipe (`|`) feeds this directly into `tar -xv` which extracts all layers
3.  Each layer contains a full filesystem snapshot at that build stage

After extraction, you'll find a `/blobs` directory which is where Docker stores the actual content of each layer. Inside `/blobs/sha256/`, you'll find directories named with SHA256 hashes - each one represents a layer of your container image. These blobs contain:

-   The actual filesystem changes for each layer
-   Binary and text files added during image building
-   Modified configuration files
-   Application code and dependencies
-   System libraries and executables

Think of blobs as a git-like system where each blob represents a point-in-time snapshot of the filesystem changes. This structure is particularly useful for:

-   Finding files that were supposed to be deleted but persist in earlier layers
-   Tracking how files change between layers
-   Identifying when sensitive data was added or modified
-   Discovering unintended artifacts from the build process

**Pro Tip**: You can use the `manifest.json` file in the extracted contents to map between the layer IDs and their corresponding blob directories.


#### Accessing Blob Contents: {#accessing-blob-contents}

Each blob in `/blobs/sha256/` is actually a tar archive that can be extracted. Here's how to access and analyze them:

1.  **Option 1 extract the contents of the blob/layer to a folder**:
    ```bash
    # Navigate to the blob directory
    cd blobs/sha256/

    # Make directory to extract blobs to:
    mkdir layer_contents

    # Extract a specific layer (blob)
    tar xf <blob-hash> -C ./layer_contents

    ```

    -   {{< figure src="/ox-hugo/2025-03-11-121204_.png" >}}

2.  **Or extract and analyze in one go using tar's streaming capability**:
    ```bash
    # Or extract and analyze in one go using tar's streaming capability
    tar tvf <blob-hash> | grep -i "interesting_file"

    # For compressed layers (common in newer images), use
    tar xzf <blob-hash> -C ./layer_contents
    ```

    -   {{< figure src="/ox-hugo/2025-03-11-120957_.png" >}}

3.  **Searching within blobs**:

<!--listend-->

```bash
# List all files in a blob
tar tvf <blob-hash>

# Search for specific file types
tar tvf <blob-hash> | grep "\.conf$"

# Extract and search specific files
tar xf <blob-hash> layer/etc/passwd --to-stdout | grep -ie "root"

# For searching through all files in the layer:
tar xf <blob-hash> --to-stdout | strings | grep -ie "password\|user\|cred"

# Alternative method - extract first, then search
mkdir temp_layer && tar xf <blob-hash> -C temp_layer
grep -r "password" temp_layer/
rm -rf temp_layer  # Clean up after analysis
```

-   {{< figure src="/ox-hugo/2025-03-11-120834_.png" >}}

**Pro Tips:**

-   For binary files, always extract first, then analyze
-   The `--to-stdout` option is more reliable than `-O` for text extraction
-   +Important+: Use `strings` command selectively as it might miss encoded/compressed data


#### Check for sensitive information in docker image history: {#check-for-sensitive-information-in-docker-image-history}

```bash

# Output to screen
docker history --no-trunc image_name:tag

# Export to text file for easier ananlysis later:
docker history --no-trunc image_name:tag >> imageHistory.txt

# Use grep etc to search for strings
docker history --no-trunc image_name:tag | grep -ie "pass|user|cred"
```

The `docker history` command is a powerful tool for security analysts and pentesters. When used with the `--no-trunc` flag, it displays the complete, untruncated history of how an image was built, including every command that was used to create each layer. This can reveal sensitive information like:

-   Environment variables containing API keys or credentials
-   Installation commands that might expose version numbers of vulnerable packages
-   Temporary files or credentials that were supposed to be cleaned up but remain in earlier layers
-   URLs to internal repositories or build servers
-   Usernames and working directories that could reveal internal naming conventions

For example, you might find something like this in the history:

```text
RUN curl -u admin:SuperSecret123 http://internal-repo.company.local/setup.sh | bash
```

+Note+: Even if the credentials were removed in a later layer, they're still visible in the image history. This is why proper secrets management and multi-stage builds are crucial for container security.


### Alternative Transfer Methods {#alternative-transfer-methods}


#### Secure Registry Transfer {#secure-registry-transfer}

-   Useful for multiple images or repeated transfers

<!--listend-->

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

-   Captures runtime changes for dynamic analysis

<!--listend-->

```bash
# Run container and make changes
docker run -it --name test-container image_name:tag /bin/bash

# Export the modified container
docker export test-container > container-snapshot.tar
```


### Analysis Environment Setup {#analysis-environment-setup}


#### Basic Container Analysis {#basic-container-analysis}

-   This means tools can be mounted within the container.

<!--listend-->

```bash
# Run with security analysis tools mounted
docker run -it \
  --name analysis-container \
  -v /path/to/tools:/tools \
  --cap-add=SYS_PTRACE \
  target_image:tag
```


#### Common Analysis Options {#common-analysis-options}

| Option                            | Purpose                               |
|-----------------------------------|---------------------------------------|
| --cap-add=SYS_PTRACE              | Enable debugging capabilities         |
| --security-opt seccomp=unconfined | Disable security profiles for testing |
| -v $(pwd)/results:/results        | Mount directory for findings          |
| --network none                    | Complete network isolation            |


### Best Practices for Security Testing {#best-practices-for-security-testing}


#### Documentation {#documentation}

-   Record all modifications and findings
-   Document original image state

<!--listend-->

```bash
# Example documentation script
docker inspect image_name:tag > original_image_info.json
docker history image_name:tag > image_history.txt
```


#### Cleanup Procedures {#cleanup-procedures}

-   Remove sensitive data after analysis
-   Clean up test environments

<!--listend-->

```bash
# Cleanup script
docker rm -f $(docker ps -aq)  # Remove all containers
docker rmi -f target_image:tag  # Remove test image
docker network rm pentest-network  # Remove test network
shred -u target_image.tar     # Securely delete image file
```
