+++
tags = ["homelab", "ollama", "llm", "amd", "rocm", "gpu", "local-llm"]
draft = false
title = "How to Run Local LLMs with Ollama on AMD GPU (Complete Guide)"
description = "Step-by-step guide for running Ollama LLMs locally using AMD GPU acceleration with ROCm support on Arch Linux. Includes installation, configuration, and troubleshooting tips."
keywords = "Ollama, AMD GPU, ROCm, local LLM, AI, machine learning, GPU acceleration, open source AI, self-hosted LLM"
author = "bloodstiller"
date = 2025-03-10
toc = "= true"
bold = "= true"
next = "= true"
+++

This is mainly being put here for reference for me. I will writeup nix instructions when I finally migrate my main system to nix, but at the moment this is on arch &amp; I wanted to document the process for myself.

I am using an AMD gpu so this may differ for you:


## Install AMD GPU backend packages: {#install-amd-gpu-backend-packages}

```shell
sudo pacman -S rocminfo rocm-opencl-sdk rocm-hip-sdk rocm-ml-sdk
```


## Install ollama with AMD GPU support. {#install-ollama-with-amd-gpu-support-dot}

```shell
yay -S ollama-rocm
```


## Start Ollama: {#start-ollama}

```shell
ollama serve
```


## Run open-webui via docker: {#run-open-webui-via-docker}

```yaml
services:
  open-webui:
    build:
      context: .
      dockerfile: Dockerfile
    image: ghcr.io/open-webui/open-webui:${WEBUI_DOCKER_TAG-main}
    container_name: open-webui
    volumes:
      - ./open-webui:/app/backend/data
    network_mode: host
    environment:
      - 'OLLAMA_BASE_URL=http://127.0.0.1:11434'
    restart: unless-stopped

volumes:
  open-webui: {}
```

-   `Docker compose up -d`


## Access Open WebUI: {#access-open-webui}

```shell
http://localhost:8080
```


## Pull A Model Down: {#pull-a-model-down}

-   {{< figure src="/ox-hugo/2025-03-10-080912_.png" >}}


## System Requirements {#system-requirements}

-   Minimum 8GB RAM (16GB+ recommended for larger models)
-   GPU with at least 6GB VRAM for running medium-sized models
-   Storage space depending on models (each model can be 3-8GB+)


## Common Model Commands {#common-model-commands}

```shell
# List all installed models
ollama list

# Remove a model
ollama rm model-name

# Get model information
ollama show model-name

# Run a model in CLI
ollama run model-name
```


## Troubleshooting {#troubleshooting}

-   If GPU is not detected, ensure ROCm drivers are properly installed and configured
-   Check logs with `journalctl -u ollama`
-   Verify Ollama service status with `systemctl status ollama`
-   Common ports used: 11434 (Ollama API), 8080 (Open WebUI)


## Additional Resources {#additional-resources}

-   Official Ollama documentation: <https://github.com/ollama/ollama/tree/main/docs>
-   Model library:  <https://ollama.com/search>
-   GitHub repository: <https://github.com/ollama/ollama>


## Introduction {#introduction}

This guide demonstrates how to run Large Language Models (LLMs) locally using Ollama with AMD GPU acceleration. While many guides focus on NVIDIA GPUs, this tutorial specifically covers AMD GPU setup using ROCm on Arch Linux. Running LLMs locally provides better privacy, reduced latency, and no API costs.


## Performance Optimization {#performance-optimization}


### AMD GPU-Specific Settings {#amd-gpu-specific-settings}

-   Ensure ROCm is properly detecting your GPU: `rocminfo`
-   Monitor GPU usage: `rocm-smi`
-   Check GPU temperature: `sensors`


### Model Optimization {#model-optimization}

-   Use quantized models (e.g., q4_0, q4_1) for better performance
-   Adjust context length based on your VRAM
-   Consider model size vs. performance tradeoffs
