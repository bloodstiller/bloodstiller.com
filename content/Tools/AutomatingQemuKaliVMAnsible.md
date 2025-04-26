+++
title = "Automating Kali Linux VM Setup: A Comprehensive Guide to QEMU and Ansible Integration"
draft = false
tags = ["kali", "automation", "qemu", "ansible", "dotfiles"]
keywords = ["Kali Linux automation", "QEMU VM setup", "Ansible configuration", "Kali VM provisioning", "VirtioFS integration", "Kali development environment", "Kali security tools", "Kali dotfiles", "Kali VM management", "Kali automation workflow"]
description = "A comprehensive guide to automating Kali Linux virtual machine setup using QEMU and Ansible. Learn how to create a consistent, reproducible environment with automated tool installation, dotfiles configuration, and development environment setup."
author = "bloodstiller"
date = 2025-02-03
toc = true
bold = true
next = true
+++

As a cybersecurity enthusiast and productivity junkie, I've always been fascinated by the power of automation. Recently, I decided to streamline my process of setting up Kali Linux virtual machines using QEMU and Ansible. In this article, I'll walk you through how I've automated the creation and configuration of Kali VMs, complete with my preferred dotfiles and tools.


## The Need for Automation {#the-need-for-automation}

If you're like me, you probably find yourself creating new Kali VMs frequently for various projects or testing environments. The process of setting up a new VM, updating the system, installing your favorite tools, and configuring your environment can be time-consuming and repetitive. That's where automation comes in handy.
You can repurpose this setup for other projects, just change the Ansible playbook and dotfiles.


## Benefits and Challenges {#benefits-and-challenges}

This automation setup offers several advantages:

1.  Consistent environment across all VMs
2.  Rapid deployment of new instances
3.  Version-controlled configuration (infrastructure as code)
4.  Easy sharing and collaboration

Some challenges I encountered:

-   VirtioFS setup complexity
-   Ansible role organization
-   Package version management
-   Dotfiles synchronization

But the benefits far outweigh the initial setup effort.


## Prerequisites {#prerequisites}

Choose your preferred virtualization provider:


### VirtualBox Setup {#virtualbox-setup}

-   VirtualBox
-   Vagrant
-   Ansible


### QEMU/KVM Setup (Linux only) (My preferred setup) {#qemu-kvm-setup--linux-only----my-preferred-setup}

-   QEMU/KVM (≥ 4.2)
-   Libvirt (≥ 6.2.0)
-   Vagrant
-   Ansible

For QEMU/KVM shared folder support:

-   Host: Linux kernel ≥ 5.4
-   Guest: Linux kernel ≥ 5.4

-   There is some additional setup required for the `vagrant-libvirt` plugin so would advise you checkout [QEMU/KVM Setup Guide](https://github.com/bloodstiller/kaliconfigs/blob/main/Vagrant/QEMU/README.md)

#### Unable to resolve dependency `vagrant-libvirt`error:
- +Update+ 21/02/2025 
  - I recently ran an update and encountered an issue where it refused to launch new VM's. I received an error similar to the below (it was not exactly the same as I had a crash shortly after).
`Error message given during initialization: Unable to resolve dependency: user requested 'vagrant-libvirt (= 0.12.2)'`
after alot of searching I found [this post](https://warlord0blog.wordpress.com/2024/08/21/vagrant-error-after-updates/) I found following the steps resolved the issue.
``` bash
vagrant plugin repair
vagrant plugin expunge --reinstall
vagrant plugin update

VAGRANT_DISABLE_STRICT_DEPENDENCY_ENFORCEMENT=1 vagrant plugin install vagrant-libvirt

```


## The Automation Stack {#the-automation-stack}

My automation setup consists of three main components:

1.  Vagrant for VM provisioning
2.  QEMU/KVM for virtualization
3.  Ansible for configuration management

Let's dive into each component.


### 1. Vagrant with QEMU/KVM {#1-dot-vagrant-with-qemu-kvm}

I chose QEMU/KVM over VirtualBox for several reasons:

-   Better performance on Linux hosts
    -   Once you have used KVM/QEMU you will never go back to VirtualBox etc.
-   Native virtualization support
-   VirtioFS for efficient file sharing

The Vagrantfile handles:

-   VM resource allocation (RAM, CPU)
-   Network configuration
-   Shared folder setup with VirtioFS
-   Ansible provisioner integration

Here's the the Vagrantfile:

{{< ghcode "https://raw.githubusercontent.com/bloodstiller/kaliconfigs/refs/heads/main/Vagrant/QEMU/Vagrantfile" >}}


### 2. Ansible Configuration {#2-dot-ansible-configuration}

Ansible automates the entire VM setup process. The main playbook handles:

1.  System updates and package installation
2.  Development tools setup
3.  Security tools installation
4.  Terminal environment configuration (Alacritty, Tmux)
5.  Editor setup (Doom Emacs)
6.  Dotfiles deployment

Here's the main Ansible playbook:

{{< ghcode "https://raw.githubusercontent.com/bloodstiller/kaliconfigs/refs/heads/main/Ansible/configure-kali.yml" >}}


### 3. Dotfiles and Tool Configuration {#3-dot-dotfiles-and-tool-configuration}

The automation includes configuration for:

-   Alacritty terminal emulator
-   Tmux with custom keybindings
-   Doom Emacs with security-focused packages
-   Starship cross-shell prompt
-   Zsh with Oh My Zsh

Each tool has its own configuration module in the repository:

-   [Alacritty Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Alacritty)
-   [Tmux Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Tmux)
-   [Doom Emacs Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Doom)
-   [Starship Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Starship)
-   [Zsh Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Zsh)


## Included Tools &amp; Features {#included-tools-and-features}

The automation sets up a comprehensive environment with:


### Security Tools {#security-tools}

-   SecLists (lots of lists)
-   Kerbrute for Kerberos authentication testing
-   Statistically Likely Usernames wordlist
-   Common pentesting tools (I have my folders for linux &amp; windows tools (I will make a repo for that soon))
-   Bloodhound for Active Directory analysis (dockerized)


### Development Environment {#development-environment}

-   Emacs 29.4 with native compilation
-   Doom Emacs configuration
    -   This is my main editor and I use it for everything but if you prefer another editor you can change the Ansible playbook.
-   Git version control
-   Docker and Docker Compose
-   Build tools and development libraries


### Modern Terminal Experience {#modern-terminal-experience}

-   Alacritty terminal emulator
-   Starship cross-shell prompt
-   Tmuxinator for session management


### Command Line Improvements {#command-line-improvements}

-   Eza (modern ls replacement)
-   Bat (better cat)
-   Ripgrep for searching
-   fd-find for file discovery
-   Enhanced Zsh configuration:
    -   zsh-autosuggestions
    -   zsh-syntax-highlighting
    -   zsh-autocomplete
    -   fast-syntax-highlighting


## Getting Started {#getting-started}

To use this automation:

1.  Clone the repository:
    ```shell
       git clone https://github.com/bloodstiller/kaliconfigs.git
       cd kaliconfigs
    ```

2.  Install prerequisites:
    ```shell
       # For Debian/Ubuntu
       sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients vagrant ansible

       # For Arch Linux
       sudo pacman -S qemu-full libvirt vagrant ansible
    ```

3.  Start the VM:
    ```shell
       cd Vagrant/QEMU
       vagrant up
    ```


## Development Workflow {#development-workflow}

For efficient development and testing:

1.  Rerun only Ansible playbooks:
    ```bash
       vagrant provision
    ```

2.  Run Ansible directly against the VM:
    ```bash
       vagrant ssh-config > vagrant-ssh-config
       ansible-playbook -i .vagrant/provisioners/ansible/inventory/vagrant_ansible_inventory Ansible/configure-kali.yml
    ```

3.  Use snapshots for safe testing:
    ```bash
       vagrant snapshot save baseline
       vagrant snapshot restore baseline
    ```


## Customization Options {#customization-options}

The automation is highly customizable:

1.  VM Resources (Vagrantfile):
    ```ruby
       config.vm.provider :libvirt do |libvirt|
         libvirt.memory = 8192
         libvirt.cpus = 4
       end
    ```

2.  Package Selection (Ansible):
    ```yaml
    ​   - name: Install base packages
         apt:
           name:
    ​         - eza
    ​         - alacritty
    ​         - git
             # Add your packages here
    ```

3.  Shared Folders:
    ```ruby
       config.vm.synced_folder "/path/to/host", "/path/in/guest",
         type: "virtiofs"
    ```


## Documentation &amp; Resources {#documentation-and-resources}

For detailed setup and configuration instructions, refer to:

-   [Main Project Documentation](https://github.com/bloodstiller/kaliconfigs/blob/main/README.md) - Overview and quick start guide
-   [Ansible Configuration Guide](https://github.com/bloodstiller/kaliconfigs/blob/main/Ansible/README.md) - Detailed playbook customization
-   [QEMU/KVM Setup Guide](https://github.com/bloodstiller/kaliconfigs/blob/main/Vagrant/QEMU/README.md) - QEMU-specific installation and configuration
-   [Alacritty Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Alacritty) - Terminal emulator setup
-   [Doom Emacs Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Doom) - Editor configuration
-   [Tmux Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Tmux) - Terminal multiplexer setup
-   [Starship Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Starship) - Shell prompt customization
-   [Zsh Configuration](https://github.com/bloodstiller/kaliconfigs/tree/main/Zsh) - Shell configuration and plugins


## Conclusion {#conclusion}

Automating Kali VM setup with QEMU and Ansible has significantly improved my workflow. The combination of Vagrant for VM management, QEMU for virtualization, and Ansible for configuration provides a powerful and flexible automation stack.

The complete code is available in my [kaliconfigs repository](https://github.com/bloodstiller/kaliconfigs). Feel free to fork it and adapt it to your needs.

Happy hacking!
