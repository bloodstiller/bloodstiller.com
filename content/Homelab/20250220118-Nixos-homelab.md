+++
draft = false
tags = ["nixos", "tailscale", "homelab"]
title = "Rebuilding My Homelab In NixOS (Part 1) Creating the NixOS VM"
author = "bloodstiller"
date = 2025-02-26
toc = true
bold = true
next = true
+++

## The Catalyst: {#the-catalyst}

I have stepped away from doing writeups for a little while, purely due to wanting to mix things up and the fact that I was just grinding for a year prior to get my CPTS certification; I actually have a number of writeups for active boxes written just not on the site due to the terms and conditions by HTB. And as I needed something else to spend my time with I created a Proxmox cluster using two nodes (I know I know you need 3 nodes for it actually be a cluster) &amp; also set up a Proxmox backup server. However that took all of an hour to do, honestly, it was one of the easiest setups I have ever done (I will create a writeup for this soon enough.)

As the Proxmox cluster setup was painless I needed another project. I decided to migrate my containers from Truenas Scale to a Virtual Machine in the Proxmox cluster, with a separate drive being mounted to the VM to host all the docker data. The reason being is that although I like Truenas Scale &amp; their apps I don't like the fact that I have to configure things with a GUI. I want to be able to create a docker `compose.yml` file with all the services I want to run and simply run `docker compose up -d`. This approach means that I can also commit the `compose.yml` to git for version control and if I ever need to rebuild, I can just spin up another VM, git-clone the repo &amp; re-mount the data drive. This also means I can have the data drive backed up with the Proxmox backup server. Another primary driver for this approach has been due to me working more with Ansible &amp; Docker at my workplace as means to create reproducible builds.

So I did this, created the Ubuntu VM &amp; additional drive in Proxmox, installed docker &amp; docker compose, wrote the `compose.yml`, transferred the existing docker data from Truenas scale, and everything was working perfectly. I had my media server, reverse proxy etc and things were ticking over nicely for all of an hour...until I heard the voice "NixOS.....join us for truly reproducible builds and version controlled configuration files" thus began my journey with NixOS. Because why use continue to use a perfectly working system when I can switch to a new distro/OS (where it turns out even though I have been working with arch as my daily driver for years I will have a STEEP learning cure) and struggle to get things running.


## Why NixOS: {#why-nixos}


### Reason 1: Single Source of Truth: {#reason-1-single-source-of-truth}

-   Initially I was drawn to the idea of having a single configuration file, that was a single source of truth. If you wanted to change something about your system you just modified a single file and rebuilt the host, simple.
    -   Now, that is and is not kind of true. You can 100% do that with a `configuration.nix` stored in `/etc/NixOS` and control your entire system from that, which I have done for my homelab.
        -   Since creating the homelab I have also migrated my laptop to NixOS &amp; that was a bit more involved...thanks `home-manager` but I will create a separate post for that.
    -   While you can use a single configuration file `configuration.nix`, NixOS supports modularizing your configuration into multiple files that can be imported. This makes it much easier to organize and maintain larger configurations while still maintaining the "single source of truth" principle.
    -   This declarative approach means you can easily replicate the exact same system state across multiple machines - perfect for maintaining consistency across a homelab.
    -   Since your entire system configuration is just text files, you can version control it with Git,  making it easy to track changes over time.


### Reason 2: Immutable Builds: {#reason-2-immutable-builds}

-   NixOS uses a unique approach where all packages are stored in the Nix store (`/nix/store`) with cryptographic hashes as part of their paths. While users can still modify their home directories and data, the system packages and configurations managed by Nix **cannot be modified after they're built**.
-   This immutability prevents "dependency hell" since different versions of packages can coexist without conflict - each package has its own unique path in the Nix store.
    -   In a cruel twist of fate I had this issue this morning; I am currently still running arch linux on my desktop (the transition takes a little more planning for this machine) and I have encountered dependency hell, this has only happened to me a 3/4 times since running arch linux but I wouldn't get this on Nix.
        -   {{< figure src="/ox-hugo/2025-02-21-080244_.png" >}}
-   For security reasons, this immutability is amazing. Since system packages can't be modified after installation, it's much harder for an adversary to create backdoors or elevate privileges by modifying system binaries.
-   The immutable nature of builds also ensures reproducibility - given the same inputs, you'll get the same outputs every time, which is crucial for reliable system management.


### Reason 3: Easily Roll-back to Previous Configuration: {#reason-3-easily-roll-back-to-previous-configuration}

-   NixOS keeps versions (called generations) every time you rebuild your system, meaning that if you have an issue you can roll-back to a previous working configuration without issue by easily rebooting; the trade-off is this does require additional storage. However, these versions can be deleted.
    -   By default, NixOS keeps 20 generations to prevent unlimited disk usage, but this is configurable &amp; generations can be manually deleted.
-   Rollbacks aren't just for system configurations - you can roll back individual packages as well.
-   You can boot into any previous generation directly from the GRUB menu, making it easy to recover from problematic configurations.


### Additional Benefits: {#additional-benefits}

-   System updates are atomic - they either complete successfully or not at all, eliminating the risk of ending up with a partially updated system "dependency hell"
-   The `nix-shell` feature lets you try packages without installing them system-wide, perfect for testing or development environments or quickly running a package.
    -   For instance like below I wanted to quickly get an overview of the folder/file structure of the directory I was in but did not have `tree` installed, so I run `nix-shell tree -p` and I am placed into temporary environment with the program installed, I can run it as expected.
    -   {{< figure src="/ox-hugo/2025-02-21-075244_.png" >}}
    -   Once I have finished I just type "`exit`" and the package is removed, temporary environment destroyed and I no longer have access it to it.
        -   {{< figure src="/ox-hugo/2025-02-21-075520_.png" >}}


#### Flakes: {#flakes}

-   It would be rude if I did not mention flakes, and I could possible incur the ire of the nix community (who are from what I have found, very nice actually, see <https://discourse.nixos.org/>
    -   While not needed for this basic homelab setup, Nix Flakes provide an "experimental"\* but powerful way to make Nix configurations even more reproducible and portable. They work by creating a `flake.lock` file (similar to `package-lock.json` in `Node.js` or `Cargo.lock` in Rust) that pins the exact git commit hashes of all your dependencies, including nixpkgs itself. This means that even if you come back to your configuration months later, you'll get exactly the same build. I use them in my other setups for this predictability, **but they're completely optional** and the traditional approach works great for getting started and also not required for this setup. They also make it easier to share and reuse configurations between machines since **each flake is a self-contained unit with all its dependencies explicitly declared.**
        -   \* they are labeled as experimental but they really aren't now, they have wide adoption.


## Creating the NixOS VM: {#creating-the-nixos-vm}


### Download the NixOS ISO: {#download-the-nixos-iso}

-   First we are going to need an ISO file go with the Minimal ISO at the bottom of the page.
    -   <https://nixos.org/download/#NixOS-iso>
    -   {{< figure src="/ox-hugo/2025-02-21-115830_.png" >}}
        -   "Why are you recommending the GUI installer if we are going to be running this headless", great question, this version comes with a simple GUI and is easier for everyone to follow than doing it via CLI, and you can elect to not install a Desktop Environment.


### Upload the NixOS ISO: {#upload-the-nixos-iso}

-   I am doing this on Proxmox, but you can do it using whatever virtualization/vps you use, just substitute these steps for whatever your preferred platform is.

-   Login to your Proxmox node/cluster and upload the image to the ISO Images storage:
    -   {{< figure src="/ox-hugo/2025-02-21-120016_.png" >}}


### Creating a VM on Proxmox: {#creating-a-vm-on-proxmox}

-   Select the Node of your cluster (if you have more than one) &amp; click "Create VM"
    -   {{< figure src="/ox-hugo/2025-02-21-072602_.png" >}}

-   Assign a Hostname:
    -   {{< figure src="/ox-hugo/2025-02-21-121117_.png" >}}
        -   I would also select start on boot so if your Proxmox instance goes down it will automatically restart the VM &amp; services on boot. (You will need to have the "Advanced" box ticked at the bottom.)

-   Installation Media:
    -   {{< figure src="/ox-hugo/2025-02-21-120121_.png" >}}
    -   Select the NixOS iso.

-   System:
    -   {{< figure src="/ox-hugo/2025-02-21-073324_.png" >}}
    -   I just used the defaults for System as I was not passing through any additional graphics card etc.

-   Storage:
    -   {{< figure src="/ox-hugo/2025-02-21-121202_.png" >}}
    -   +Important+: The default storage size for new VM's is 32GB, I would personally recommend upping this, the reason being is that, as mentioned previously, NixOS keeps versions whenever you rebuild the system VM. These versions can be deleted but if you do intend to make frequent changes or test things I would recommend upping the size of storage if you have the means.

-   CPU/Cores:
    -   As we are running fairly lightweight containers &amp; OS I found that 1 Socket &amp; 2 Cores was more than enough.
    -   {{< figure src="/ox-hugo/2025-02-21-112843_.png" >}}
    -   +Note+: My Proxmox cluster is running on Think Centre M910q's which have 7th Gen i5's so not the most robust of equipment and they handled it fine so if you think you don't have enough juice these are 6 year old CPU's.

-   Memory:
    -   I have assigned 8GB which I found was more than enough for this &amp; each of my nodes has 24GB.
    -   {{< figure src="/ox-hugo/2025-02-21-113550_.png" >}}

-   Network:
    -   {{< figure src="/ox-hugo/2025-02-21-113758_.png" >}}
    -   I left the Network tab as default however if you want to assign a dedicated NIC etc you can do that here, but my nodes have 1 Ethernet port so is not applicable.

-   At the "Confirm" screen you should have something that looks similar to the below.
    -   {{< figure src="/ox-hugo/2025-02-21-120234_.png" >}}
    -   +Note+: Ensure you do not have "Start after created" enabled as we want to add an additional drive for our docker data.


### Creating an additional drive to host our docker data: {#creating-an-additional-drive-to-host-our-docker-data}

-   The primary reason for doing this is to have data persist across changes. If I decide to change OS in the future if I have my persistent data on an external drive I can easily mount this gives me far more flexibility with the lab.
-   Click the VM, --&gt; "Hardware" --&gt; "Add" --&gt; Hard Disk
    -   {{< figure src="/ox-hugo/2025-02-21-114419_.png" >}}

-   In the new window, set the size of the drive. I opted for 40GB as this drive is mainly used to hold just docker config data. The actual main storage for my containers, like media is passed by NFS mounts from my NAS.
    -   {{< figure src="/ox-hugo/2025-02-21-115349_.png" >}}

-   Now when you look at the Hardware for the VM you should see two SCSI drives.
    -   {{< figure src="/ox-hugo/2025-02-21-115410_.png" >}}
    -   +Note+: Ignore the size of my drives, these are purely for illustrative purposes.


## Installing NixOS: {#installing-nixos}


### Start the VM: {#start-the-vm}

-   Start the host.
    -   {{< figure src="/ox-hugo/2025-02-21-121409_.png" >}}

-   Open the console.
    -   {{< figure src="/ox-hugo/2025-02-21-121454_.png" >}}


### Follow the installer prompts: {#follow-the-installer-prompts}

-   The installer is the Calameres installer so if you have ever installed Linux before you may have encountered this installer.
    -   {{< figure src="/ox-hugo/2025-02-21-121912_.png" >}}
    -   +Note+: I will not cover all steps as I hope you can select your language &amp; keyboard layout yourself if you've managed to configure Proxmox.

-   Ensure that "No desktop" is selected as it is not required for this setup.
    -   {{< figure src="/ox-hugo/2025-02-21-122433_.png" >}}

-   If you do intend to use "Unfree Software" I would tick the box, however for this setup it's not required.

-   Disks:
    -   Erase disk &amp; ensure "No Swap" is selected. I would always encourage users to Encrypt the system however this is up-to yourselves.
    -   {{< figure src="/ox-hugo/2025-02-21-122552_.png" >}}

-   Install:
    -   {{< figure src="/ox-hugo/2025-02-21-122717_.png" >}}

-   +Tip+: Click "Toggle Log" as soon as you star the install, the reason being is that the installer appears to stick at 46% percent for a lot of people whereas if you have the log viewable you can actually see it is progressing even though it may appear it is not.

    -   {{< figure src="/ox-hugo/2025-02-21-122859_.png" >}}

    <!--listend-->

    -   Once complete restart the host:
        -   {{< figure src="/ox-hugo/2025-02-21-123707_.png" >}}


## Login to NixOS: {#login-to-nixos}

-   As we are using Proxmox our first login will be using the inbuilt console, use the credentials you provided in the VM creation.
-   {{< figure src="/ox-hugo/2025-02-21-123930_.png" >}}

-   As this is already getting pretty long I will go over the configuration for the VM in my next post.

    As always hack the ~~planet~~ homelab!
