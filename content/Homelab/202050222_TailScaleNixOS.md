+++
tags = ["nixos", "tailscale", "homelab"]
title = "Autostart tailscale on NixOS system boot"
draft = false
author = "bloodstiller"
date = 2025-02-23
toc = true
bold = true
next = true
+++

Are you tired of running `sudo tailscale up` every time you login, I know I am. So I thought why spend under two seconds waiting for something to run and using auto complete with ZSH to easily find the command when I can easily create a service that launches Tailscale on boot for me and re-launches on every rebuild of the system.

**This configuration will ensure that**:

-   Tailscale starts automatically with your system.
-   You don't need to manually authenticate each time.
-   Your authentication key is stored securely using [sops](https://getsops.io/)/[sops-nix](https://github.com/Mic92/sops-nix?tab=readme-ov-file)
-   The connection is established only when needed (won't try to reconnect if already connected).

This assumes you already have a Tailscale account and sops setup, if you don't please see guides below.

-   [Tailscale quick start guide](https://tailscale.com/kb/1017/install)
-   [Install sops-nix](https://github.com/Mic92/sops-nix?tab=readme-ov-file)


## Generating The Tailscale Auth Key: {#generating-the-tailscale-auth-key}

-   As we want to automate the process of authenticating of connecting our NixOS host to the Tailscale network we will need to generate an auth key. This will mean we do not have to follow the provided Tailscale links when adding the host to the network or re-authorizing.
    -   ~~Note~~: Even if you have already added your host to the Tailscale network this process is still the same.

Login to your account and click "Settings" --&gt; "Personal Settings" --&gt; "Keys" --&gt; "Generate Auth Key"

-   {{< figure src="/ox-hugo/2025-02-22-162839_.png" >}}

Key settings, give your key a memorable name and also set it for the amount of time you want it to be valid for, I have set it for the max 90 days have added a reminder to my todo list to regenerate one in 85 days.

-   {{< figure src="/ox-hugo/2025-02-23-075334_.png" >}}

You should now have a Tailscale auth key.

-   {{< figure src="/ox-hugo/2025-02-22-162726_.png" >}}


## Adding Tailscale Auth Key To Sops: {#adding-tailscale-auth-key-to-sops}

It's now time to add our Tailscale Auth Key to sops so our system has access to it.

```shell
# If your sops file is called something different obviously you need to enter that...
sops secrets.yaml

# Store it in this format is important as we will be calling it later as a variable
tailscale_preauth: |
    TAILSCALE_AUTH_KEY=tskey-auth-xxxxx-xxxxxxxxxxxxx
```

-   {{< figure src="/ox-hugo/2025-02-22-171514_.png" >}}
-   ~~Note~~: It is also possible to use age for this however I personally use stops as it also allows integration with home-manager.

Edit your `configuration.nix` and add the secret so it's accessible by other services.

```nix
  sops = {
    defaultSopsFile = ./packages/sops/secrets.yaml;
    age.keyFile = "/home/martin/.config/sops/age/keys.txt";
    # I have other sops secerts here but have removed for brevity
    secrets.tailscale_preauth = { };
  };
```

-   ~~Important~~: The part `secrets.tailscale_preauth` has to match name that was placed into the sops `secrets.yaml` as this is the key for the value referenced. So if in your sops secrets file you called it `ts-key` you would write `secrets.ts-key`
-   ~~Note~~:
    -   This has to be done in `configuration.nix` &amp; not home-manager as this is a system wide service that is running and not a user specific service.


## Creating The Tailscale Service: {#creating-the-tailscale-service}

-   Edit your NixOS `configuration.nix` and add the below service.

<!--listend-->

```nix

# Add tailscale to your system packages
environment.systemPackages = [ pkgs.tailscale ];

# Enable the tailscale service
services.tailscale.enable = true;

# Create a oneshot to autoconnect on rebuild/switch
systemd.services.tailscale-autoconnect = {
  description = "Automatic connection to Tailscale";

  after = [ "network-pre.target" "tailscale.service" ];
  wants = [ "network-pre.target" "tailscale.service" ];
  wantedBy = [ "multi-user.target" ];

  serviceConfig = {
    Type = "oneshot";

    # Pass our tailscale auth key from sops as a Environmental Variable
    EnvironmentFile = config.sops.secrets.tailscale_preauth.path;
  };

  # have the job run this shell script
  script = with pkgs; ''
    # wait for tailscaled to settle
    sleep 2

    # check if we are already authenticated to tailscale
    status="$(${tailscale}/bin/tailscale status -json | ${jq}/bin/jq -r .BackendState)"
    if [ $status = "Running" ]; then # if so, then do nothing
      exit 0
    fi

    # otherwise authenticate with tailscale using the key from secrets
    ${tailscale}/bin/tailscale up -authkey "$TAILSCALE_AUTH_KEY" --accept-routes=true
  '';
};
```

-   ~~Important~~:
    -   As stated before if you have called your Tailscale Auth key in your secrets file something other than `tailscale_preauth` you will then have to modify the line below.
        ```nix
            # Pass our tailscale auth key from sops as a Environmental Variable
            EnvironmentFile = config.sops.secrets.tailscale_preauth.path;
        ```


### Breaking Down The Configuration: {#breaking-down-the-configuration}

Let's break down what each part of this configuration does:

1.  **System Package and Service Setup**:
    -   `environment.systemPackages = [ pkgs.tailscale ]` adds the Tailscale package to your system
    -   `services.tailscale.enable = true` enables the Tailscale daemon service

2.  **Automatic Connection Service**:
    The `systemd.services.tailscale-autoconnect` section creates a systemd service that:
    -   Runs once during system startup (`Type = "oneshot"`)
    -   Starts after networking and the Tailscale daemon are ready
    -   Loads your authentication key from the sops-encrypted file
        -   `${tailscale}/bin/tailscale up -authkey "$TAILSCALE_AUTH_KEY" --accept-routes=true`

3.  **Connection Script Logic**:
    The script section:
    1.  Waits 2 seconds for the Tailscale daemon to fully start
    2.  Checks if you're already connected to Tailscale by querying its status
    3.  If already connected (`Running` state), exits without doing anything
    4.  If not connected, authenticates using your stored auth key
    5.  Enables route acceptance with `--accept-routes=true`
        -   ~~Note~~: I also use some of my nodes as routers within my home network to allow access to other hosts so I also pass the `--accept-routes=true` argument, however if you don't do this you can omit this argument.


## Rebuilding The System: {#rebuilding-the-system}

That's it now run either:

-   `sudo nixos-rebuild switch flake [location/of/flake]`
-   `sudo nixos-rebuild switch`

Check Tailscale is running &amp; connected

-   {{< figure src="/ox-hugo/2025-02-23-080936_.png" >}}
