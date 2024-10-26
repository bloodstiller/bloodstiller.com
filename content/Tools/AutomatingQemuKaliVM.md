+++

tags = ["QEMU", "Automation", "Kali", "Bash", "Tools" ]
draft = false
title = "Automating Kali VM Setup with QEMU"
author = "bloodstiller"
date = 2024-10-26
+++

As a productivity junkie, I've always been drawn to automation. Recently, I decided to streamline my process of setting up Kali Linux virtual machines using QEMU. In this article, I'll walk you through how I've automated the creation and configuration of Kali VMs, complete with my preferred dotfiles and tools.



## The Need for Automation {#the-need-for-automation}

If you're like me, you probably find yourself creating new Kali VMs frequently for various projects or testing environments. The process of setting up a new VM, updating the system, installing your favorite tools, and configuring your environment can be time-consuming and repetitive. That's where automation comes in handy.


## The Automation Process {#the-automation-process}

**My automation setup consists of two main components**:

1.  A script to launch and set up the initial VM
2.  A script to configure the VM with my preferred settings and tools

**Let's dive into each of these components**.


### 1. Launching the VM with QEMU {#1-dot-launching-the-vm-with-qemu}

The first step in our automation process is creating and launching the VM. I've created a Bash script called `launch_kali_vm.sh` that handles this. Here's a breakdown of what it does:

1.  Sets up variables for the VM name, image location, and resource allocation
2.  Creates a new directory for the VM
3.  Copies a base Kali image to the new VM directory
4.  Launches the VM using QEMU with specified parameters

Here's the script:

{{< ghcode "https://raw.githubusercontent.com/bloodstiller/VMLaunchTemplates/refs/heads/main/KaliVMS/launch_kali_vm.sh"   >}}

This script automates the process of creating a new VM instance, ensuring that each new VM has a unique name based on the current date.

The script creates a log file in the same directory, named `Kali-YYYY-MM-DD-log.txt`, which contains details about the VM creation process.

-   +Test Mode+: I have created a test mode where you can just print out to the screen so if you are customizing this script use it.
    -   For test mode (no actual VM creation):
        -   `./launch_kali_vm.sh --test`


### 2. Configuring the VM {#2-dot-configuring-the-vm}

Once the VM is launched, we need to configure it with our preferred settings and tools. For this, I use another Bash script called `kali_setup.sh`. This script is copied to a shared folder that's accessible from within the VM. Here's what it does:

1.  Updates the system
2.  Installs necessary packages
3.  Sets up my preferred shell environment (Zsh with Oh My Zsh)
4.  Installs and configures Doom Emacs
5.  Clones and sets up my dotfiles
6.  Configures Docker
7.  Sets up mount points for shared folders

Here's the script:

{{< ghcode "https://raw.githubusercontent.com/bloodstiller/VMLaunchTemplates/refs/heads/main/KaliVMS/kali_setup.sh" >}}

This script ensures that the VM is configured with my preferred settings/dotfiles and tools, making it ready for use in no time.

-   +Test Mode+: I have created a dry-run mode where you can just print out to the screen so if you are customizing this script use it.
    -   For dry run mode:
        -   `./kali_setup.sh --dry-run`

- +Note+: There a `execute sudo apt --fix-broken install -y` line as for some reason debian will not install dropbox straight away so it's easier to run the `.deb` and then fix.

## Benefits and Challenges {#benefits-and-challenges}

This automation setup has several benefits:

1.  Saves a significant amount of time on VM setup
2.  Ensures consistency across all my Kali VMs
3.  Makes it easy to update and modify my setup process

However, it wasn't without its challenges. Some issues I encountered and solved include:

-   Ensuring proper permissions for shared folders
-   Handling network configuration differences between host systems
-   Dealing with package installation errors due to repository changes

## But ansible exists? 
"But bloodstiller why did you not use Ansible?" Well I wanted to be in a position where if I did not have access to Ansible, I could still automate the process. I will port this process to ansible soon. However I like being able to pull a kali qmemu image from online, my script, update a few variables and then I have my setup the way I like it. 


## Customizing the Scripts for Your Own Use {#customizing-the-scripts-for-your-own-use}

While these scripts are tailored to my specific setup, they can easily be modified to suit your own needs. Here are some key areas you might want to customize:


### Modifying launch_kali_vm.sh {#modifying-launch-kali-vm-dot-sh}

1.  **VM Specifications**: Adjust the RAM, CPU cores, and disk size to match your system's capabilities:
    ```shell
       RAM="8192"  # Change this to your preferred RAM size in MB
       CORES=6     # Adjust the number of CPU cores
    ```

2.  **File Paths**: Update the paths to match your system's directory structure:
    ```shell
       # Change this to the path to your base Kali image
       BASE_QCOW_IMAGE="/path/to/your/base/kali-image.qcow2"
       # Change this to the path to your VM directory
       PRODUCTION_DIR="/path/to/your/vm/directory"
    ```

3.  **Shared Folders**: Modify the shared folder locations as needed:
    ```shell
       SHARED_FOLDER="$NEW_VM_DIR/shared"
    ```


### Customizing kali_setup.sh {#customizing-kali-setup-dot-sh}

1.  **Package Installation**: Add or remove packages based on your needs:
    ```shell
       execute sudo apt install -y \
           emacs \
           eza \
           alacritty \
           git \
           bat \
           seclists \
           # Add your preferred packages here
    ```

2.  **Dotfiles**: Replace my dotfiles repository with your own:
    ```shell
       execute git clone https://github.com/yourusername/your-dotfiles.git ~/.dotfiles
    ```

3.  **Additional Tools**: Add installation commands for any other tools you use regularly:
    ```shell
       # Example: Installing a custom tool
       execute wget https://example.com/custom-tool.tar.gz
       execute tar -xzvf custom-tool.tar.gz
       execute cd custom-tool && ./install.sh
    ```

4.  **Mount Points**: Adjust the mount points and shared directories to match your setup:
    ```shell
       execute sudo mkdir -p /mnt/your-custom-mount
       execute sudo mount -t ext4 UUID=your-uuid /mnt/your-custom-mount
    ```

Remember to test the modifications thoroughly to ensure they work as expected in your environment (+the scripts have a testing mode+) 

By customizing these scripts, you can create a personalized, automated VM setup process that perfectly fits your workflow and toolset.


## Conclusion {#conclusion}

Automating the setup of Kali VMs has been a game-changer for my workflow. It allows me to quickly spin up consistent, fully-configured environments. It's a system that's efficient,easily maintainable and adaptable.

You can easily fork the [VMLaunchTemplates repository](https://github.com/bloodstiller/VMLaunchTemplates), modify the scripts to suit your needs, and iterate on the process. Before you know it, you'll have a customized setup that saves you time and headaches.

Happy hacking!
