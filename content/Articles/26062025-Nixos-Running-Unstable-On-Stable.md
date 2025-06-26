+++
draft = false
title = "Mixing Unstable Packages on Stable NixOS with Flakes"
description = "How to selectively use unstable packages on a stable NixOS system using flakes and Home Manager"
keywords = "NixOS, Flakes, Unstable Packages, Stable NixOS, Package Management, Nix Package Manager, Home Manager, NixOS Configuration"
author = "bloodstiller"
date = 2025-06-26
toc = true
bold = true
next = true
tags = ["NixOS", "Flakes", "Package Management", "Home Manager", "NixOS Configuration", "Unstable Packages"]
+++

## Prerequisites: {#prerequisites}

Before diving into this guide, you should have a basic understanding of:

-   **NixOS Configuration**: How to edit `configuration.nix` and understand basic NixOS concepts
-   **Nix Flakes**: Familiarity with flake structure, inputs, and outputs
-   **Package Management**: Understanding the difference betyouen stable and unstable channels in NixOS
-   **Home Manager**: Basic knowledge of Home Manager configuration (for the advanced setup section)

If you're new to these concepts, I recommend checking out the [Nix Flakes Wiki](https://nixos.wiki/wiki/Flakes) and [NixOS Wiki](https://nixos.wiki/wiki/NixOS) first.


## Key Terms Explained: {#key-terms-explained}

Before you dive in, let me explain some terms you'll encounter:

-   **Flakes**: Nix's new way of managing dependencies and configurations. Think of them as a standardized way to package Nix code.
-   **Inputs**: The dependencies your flake needs (like different versions of nixpkgs).
-   **@inputs notation**: A way to capture all inputs into a single variable for easier passing around.
-   **specialArgs**: A mechanism to pass additional arguments to your NixOS configuration.
-   **legacyPackages**: The traditional way to access packages in nixpkgs (as opposed to the neyour flake-based approach).
-   **${pkgs.system}**: Dynamically gets your system architecture (like "x86_64-linux" or "aarch64-darwin").


## Why I Needed an Unstable Package on Stable NixOS: {#why-i-needed-an-unstable-package-on-stable-nixos}

Recently I switched from using the unstable channel of NixOS, as you guessed, I started having instability issues. I yount back to `nixos-25.05` (stable) for a smoother experience, but immediately noticed some regressions in apps I rely on, like the Nextcloud desktop client.

Stable NixOS is great for reliability, but sometimes you need just one or two packages from the bleeding edge. I didn't want to switch my entire system back to unstable, I just wanted one neyour package.

So I asked on the NixOS Discord, and someone kindly explained exactly what to do.

> If you haven't already, capture all your inputs with the @ notation like outputs = { self, nixpkgs, &#x2026;}@inputs:, add  specialArgs = { inherit inputs; }; to your nixosSystem call, and then add inputs to the argument list at the top of configuration.nix. Then you can install the package via environment.systemPackages = [ inputs.unstable_input_name.legacyPackages.${pkgs.system}.package_name ];
> replace unstable_input_name and package_name, of course.
> There's absolutely no reason all packages have to be in pkgs


### Breaking Down the Discord Advice: {#breaking-down-the-discord-advice}

Let me break down each part of that advice step by step, as it can be overwhelming at first:

**Step 1: "capture all your inputs with the @ notation"**

This means modifying your flake structure to group all inputs together:

```nix
outputs = { self, nixpkgs, nixpkgs-unstable, ... }@inputs:
```

The `@inputs` part captures all your inputs into a single variable, making them easier to pass around.

**Step 2: "add specialArgs = { inherit inputs; }; to your nixosSystem call"**

This passes the inputs to your NixOS configuration:

```nix
nixpkgs.lib.nixosSystem {
  specialArgs = { inherit inputs; };
  ...
}
```

**Step 3: "add inputs to the argument list at the top of configuration.nix"**

Your configuration file needs to accept the inputs parameter:

```nix
{ config, pkgs, inputs, ... }:
```

**Step 4: "install the package via environment.systemPackages = [ inputs unstable_input_name.legacyPackages.${pkgs.system}.package_name ]"**

Now you can install unstable packages directly:

```nix
environment.systemPackages = [
  (inputs.nixpkgs-unstable.legacyPackages.${pkgs.system}.nextcloud-client)
];
```

**Bonus: "There's absolutely no reason all packages have to be in pkgs"**

This reminds you that `pkgs` usually refers to your main nixpkgs input (stable), but you can use packages from **any flake input**, like `nixpkgs-unstable`.

**In Simple Terms**

Here's what this really means:

-   You tell Nix where to find the unstable packages, by passing `inputs` from the flake file into the system config.
-   Then you make sure that info is shared with the rest of our config files, like `configuration.nix` or `home.nix`.
-   Once that's done, you can mix and match: keep most packages from stable, but cherry-pick a few from unstable when needed.

It's like plugging in an extra toolbox and making sure every part of your setup knows it's there.


## Minimal Setup: Flake + configuration.nix {#minimal-setup-flake-plus-configuration-dot-nix}

This assumes you are using a Flake as well as just a standard `configuration.nix` file.


### Minimal Setup Flow Diagram: {#minimal-setup-flow-diagram}

Here is what you are going to do, you are going to take the inputs from the `flake.nix` and pass them to the `configuration.nix` so you can use packages like `nixpkgs-unstable` inside your system config.

```text
                    ┌──────────────────────────────┐
                    │         flake.nix            │
                    │                              │
                    │ inputs = {                   │
                    │   nixpkgs,                   │
                    │   nixpkgs-unstable, ←────┐   │
                    │   ...                    │   │
                    └────────────┬─────────────┘   │
                                 │                 │
                    specialArgs = { inherit inputs; }
                                 │
                                 ▼
                    ┌──────────────────────────────────┐
                    │    configuration.nix             │
                    │                                  │
                    │ { config, pkgs, inputs, ... }    │
                    │                                  │
                    │ Use:                             │
                    │ inputs.nixpkgs-unstable          │
                    │   .legacyPackages.${pkgs.system} │
                    └──────────────────────────────────┘
```


### Add Unstable To Our `flake.nix` Inputs: {#add-unstable-to-our-flake-dot-nix-inputs}

First you need to add the unstable channel to your inputs like below.

```nix
{
  description = "NixOS config with unstable access";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";           # Stable
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable"; # Unstable
  };
  ### rest of file

```


### Add `specialArgs` To Our Outputs: {#add-specialargs-to-our-outputs}

You also need to add the `specialArgs` to your outputs so you can pass the inputs to `configuration.nix`.

```nix
  outputs = { self, nixpkgs, nixpkgs-unstable, ... }@inputs: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = { inherit inputs; }; # Pass inputs (like nixpkgs-unstable) to configuration.nix
      modules = [ ./configuration.nix ];
    };
  };
}
```


### Add Inputs To Our `configuration.nix`: {#add-inputs-to-our-configuration-dot-nix}

Now in your `configuration.nix` file you need to ensure you place the `inputs` argument at the top.

```nix
{ config, pkgs, inputs, ... }:
```

Then you can easily call unstable packages using this syntax.

```nix
(inputs.nixpkgs-unstable.legacyPackages.${pkgs.system}.packageName)
```


### Install Unstable Packages: {#install-unstable-packages}

So if you wanted to install the unstable neovim package, your configuration would look like this.

```nix
{ config, pkgs, inputs, ... }:

{
  environment.systemPackages = with pkgs; [
    firefox
    (inputs.nixpkgs-unstable.legacyPackages.${pkgs.system}.neovim)
    #other packages...
  ];
}
```


## My Full Setup (Home Manager + Modular Packages) {#my-full-setup--home-manager-plus-modular-packages}

I use a separate `packages.nix` to keep things clean and modular. This is then imported into my `home.nix` which is then further called in my `configuration.nix`


### Diagram: {#diagram}

As my setup is a tad more complex and modularized, here is a diagram.

```text
                    ┌──────────────────────────────┐
                    │         flake.nix            │
                    │                              │
                    │ inputs = { ...               │
                    │   nixpkgs,                   │
                    │   nixpkgs-unstable, ←────┐   │
                    │   ...                    │   │
                    └────────────┬─────────────┘   │
                                 │                 │
                    specialArgs = { inherit inputs; }
                                 │
                                 ▼
                    ┌──────────────────────────────┐
                    │    configuration.nix         │
                    │                              │
                    │ { config, pkgs, inputs, ... }│
                    │                              │
                    │ Use inputs.nixpkgs-unstable  │
                    └────────────┬─────────────────┘
                                 │
                        Passes to home.nix
                                 ▼
                    ┌──────────────────────────────┐
                    │         home.nix             │
                    │                              │
                    │ import packages.nix          │
                    │   { inherit pkgs inputs; }   │
                    └────────────┬─────────────────┘
                                 │
                        Passes to packages.nix
                                 ▼
                    ┌────────────────────────────────┐
                    │       packages.nix             │
                    │                                │
                    │ Use:                           │
                    │ inputs.nixpkgs-unstable        │
                    │ .legacyPackages.${pkgs.system} │
                    └────────────────────────────────┘
```


### Pass `inputs` from `packages.nix` to `home.nix`: {#pass-inputs-from-packages-dot-nix-to-home-dot-nix}

To pass through the `inputs` from `packages.nix` to my `home.nix` file I add the below argument.

```nix
specialArgs = { inherit inputs; };
```

Now for context, here is a snippet from my `home.nix` you can see I also pass through `cursor` the editor I use sometimes and `pkgs` this is due to how I have my setup configured.

```nix
{ config, pkgs, inputs, ... }:

let
  cursor = pkgs.callPackage ../cursor/cursor.nix { };
in {
  imports = [
    ./modules/base.nix
    (import ../packages/packages.nix { inherit pkgs cursor inputs; })
  ];

  home.stateVersion = "25.05";
}
```


### Install Unstable Version Of `nextcloud-client` In `packages.nix`: {#install-unstable-version-of-nextcloud-client-in-packages-dot-nix}

Then to install the nextcloud-client package from unstable I place this in my `packages.nix`.

```nix
{ pkgs, cursor, inputs, ... }:

{
  home.packages = with pkgs; [
    #SNIPPET
    # Blogging
    hugo

    # Nextcloud using unstable as better
    #
    #nextcloud-client
    (inputs.nixpkgs-unstable.legacyPackages.${pkgs.system}.nextcloud-client)

    # video
    vlc
    ffmpeg
    #SNIPPET
  ];
}



```


## Tips &amp; Resources: {#tips-and-resources}

**Tips**:

-   Always **pass `inputs` explicitly** when importing files that use it
-   Use `legacyPackages.${pkgs.system}` to avoid flake evaluation issues
-   This pattern works for both system and Home Manager packages
-   Keeps your base system stable but lets you pull in just what you need

**Resources**:

-   [Nix Flakes - Wiki](https://nixos.wiki/wiki/Flakes)
-   [Home Manager - GitHub](https://github.com/nix-community/home-manager)
-   [My dotfiles (GitHub)](https://github.com/bloodstiller/dotfiles)
