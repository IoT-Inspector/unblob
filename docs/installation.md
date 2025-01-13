---
hide:
  - navigation
---

# Installation

Unblob consists of two main parts:

- unblob, the Python package.
- extractor command line tools like `7zip`, `unar`, etc. (See [Extractors](./extractors.md) for explanation.)

All of these need to be installed to make unblob fully functional.  
Depending the packaging solution you choose, you might need to
install external extractors manually.

## Python package

unblob can be installed (without the extractors) from PyPI (Python Package Index).  
This might be the easiest method, depending on whether you have Python 3 installed already.

1.  First, install the Python package:

        python3 -m pip install --user unblob

    This will install the `unblob` script in `~/.local/bin`. You can put that
    directory in your `PATH` environment variable, or call it directly.

    !!! Warning

        System-wide installation (with `sudo`) is not recommended, because it can potentially break your system.

2.  Make sure to [install extractors](#install-extractors).

3.  Check that everything works correctly:

        unblob --show-external-dependencies

## Kali Linux

If you're on Kali Linux, unblob is available through the [distribution
repository](https://www.kali.org/tools/unblob/). You can install it with:

```
apt install unblob
```

## Docker image

unblob can be used right away from a `docker` image: `ghcr.io/onekey-sec/unblob:latest`,
which contains everything needed to run unblob, even the [extractors](extractors.md).

The `--pull always` option is recommended, because the project is currently under heavy development, so we expect frequent changes.

The extracted files will be in the `/data/output` folder inside the container. Mount
your host directory where you want to see the extracted files there:

```console
docker run \
  --rm \
  --pull always \
  -v /path/to/extract-dir/on/host:/data/output \
  -v /path/to/files/on/host:/data/input \
ghcr.io/onekey-sec/unblob:latest /data/input/path/to/file
```

Help on usage:

```shell
docker run --rm --pull always ghcr.io/onekey-sec/unblob:latest --help
```

⚠️  When you bind mount directories from the host in the container using the `-v` option, you must
make sure that they are owned by the same `uid:gid` pair otherwise you'll get
into permission issues.

If you're on a multi-user Linux host (i.e. your $UID is > 1000), it's recommended you
launch the container this way to map the container user's UID to yours:

```console
docker run \
  --rm \
  --pull always \
  -u $UID:$GID
  -v /path/to/extract-dir/on/host:/data/output \
  -v /path/to/files/on/host:/data/input \
ghcr.io/onekey-sec/unblob:latest /data/input/path/to/file
```

## Nix package

You can install stable releases of unblob directly from nixpkgs using your preferred package installation method, e.g:

For a system-wide installation on [NixOS](https://nixos.org):

```nix
# configuration.nix

{ pkgs, ...}:

{
  environment.systemPackages = [ pkgs.unblob ];
}
```

For [home-manager](https://nix-community.github.io/home-manager/):

```nix
# home.nix

{ pkgs, ...}:

{
  home.packages = [ pkgs.unblob ];
}
```

Using `nix-env`:

```console
$ nix-env -iA nixpkgs.unblob
```

Or `nix profile`:
```console
$ nix profile install nixpkgs#unblob
```

Alternatively you can also install the latest version from git:

Using the provided overlay:

```nix
{
  nixpkgs.overlays = [
    (let
      unblob = import (builtins.fetchTarball {
        url = "https://github.com/onekey-sec/unblob/archive/main.tar.gz";
      });
    in
      "{unblob}/overlay.nix")
  ];

  environment.systemPackages = [ pkgs.unblob ]; # or `home.packages` for home-manager
}
```

You can use the provided flake as well:

```nix
{
  inputs.nixpkgs.url = "...";
  inputs.unblob.url = "github:onekey-sec/unblob";

  outputs = { nixpkgs, unblob, ...}: {
    nixosConfiguration.<my-host> = nixpkgs.lib.nixosSystem {
      modules = [
        ({ pkgs, ... }: {
          environment.systemPackages = [ unblob.packages.${pkgs.system}.default ];
        })
      ];
    };
  };
}
```

For imperative package installation, follow these steps:

1.  _Optional_: enable the experimental features so that you don't need to pass  
    `--extra-experimental-features "nix-command flakes"` to `nix` command invocations:

          mkdir -p ~/.config/nix
          cat > ~/.config/nix/nix.conf <<EOF
          experimental-features = nix-command flakes
          EOF

1.  Install unblob:

        $ nix profile install github:onekey-sec/unblob
        do you want to allow configuration setting 'extra-substituters' to be set to 'https://unblob.cachix.org' (y/N)? y
        do you want to permanently mark this value as trusted (y/N)? y
        do you want to allow configuration setting 'extra-trusted-public-keys' to be set to
        'unblob.cachix.org-1:5kWA6DwOg176rSqU8TOTBXWxsDB4LoCMfGfTgL5qCAE=' (y/N)? y
        do you want to permanently mark this value as trusted (y/N)? y

    Using and trusting substituter (binary cache) and its public key is optional but greatly speeds up installation.

- Check that everything works correctly:

        unblob --show-external-dependencies

## From source

1.  Install [Git](https://git-scm.com/download/) if you don't have it yet.
2.  Install [uv](https://docs.astral.sh/uv/getting-started/installation/) Python package manager.
3.  **Clone** the unblob **repository from GitHub**:

        git clone https://github.com/onekey-sec/unblob.git

4.  Install **Python dependencies** with uv:

    1.  Python packages:

            cd unblob
            uv sync --no-dev

    2.  Make sure you [installed all extractors](#install-extractors).

    3.  Check that everything works correctly:

            uv run unblob --show-external-dependencies

## Install extractors

There is a handy `install-deps.sh` script included in the repository and PyPI packages that can be used to install the following dependencies.

1.  With your operating system package manager:  
    On Ubuntu 22.04, install extractors with APT:

        sudo apt install android-sdk-libsparse-utils e2fsprogs p7zip-full unar zlib1g-dev liblzo2-dev lzop lziprecover libhyperscan-dev zstd lz4

2.  If you need **squashfs support**, install sasquatch:

        curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_$(dpkg --print-architecture).deb"
        sudo dpkg -i sasquatch_1.0.deb
        rm sasquatch_1.0.deb

4. We maintain a fork of e2fsprogs based on Debian upstream, with some security fixes. You can install it this way:

        curl -L -o e2fsprogs_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/e2fsprogs_1.47.0-3.ok2_$(dpkg --print-architecture).deb"
        curl -L -o libext2fs2_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libext2fs2_1.47.0-3.ok2_$(dpkg --print-architecture).deb"
        curl -L -o libss2_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libss2_1.47.0-3.ok2_$(dpkg --print-architecture).deb"
        sudo dpkg -i libext2fs2_1.47.0-3.ok2.deb libss2_1.47.0-3.ok2.deb
        sudo dpkg -i e2fsprogs_1.47.0-3.ok2.deb
        rm -f libext2fs2_1.47.0-3.ok2.deb libss2_1.47.0-3.ok2.deb e2fsprogs_1.47.0-3.ok2.de

   In case you already had e2fsprogs installed, you might need to upgrade some more packages from e2fsprogs.
   You can get the names of the installed e2fsprogs binary packages this way:

        sudo dpkg-query -W -f '${db:Status-Abbrev}\t${source:Package}\t${Package}\n' | grep '^i...e2fsprogs' | cut -f3
