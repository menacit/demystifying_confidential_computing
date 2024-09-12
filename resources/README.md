# SEV-SNP lab environment


## Introduction
Watch the presentation, basically! If you just wanna get started, run the "make" command.


## Prerequisites
- Account at [Vultr cloud](https://www.vultr.com/) with \>=50 USD deposited
- Vultr API key generated and set as the environment variable "VULTR\_API\_KEY"
- GNU Make and Docker/Podman installed
- 45GB of free disk space (only required for _local build_, see "Build options" section below)


## Build options
Before you can get started playing with confidential VMs and remote attestation, a bunch of
software components must be built/assembled. By default, this is done inside a container on your
local system.

While the local build option is cheap (as it can be done before deploying infrastructure in the
cloud), it may take a looong time (several hours) depending on your system. Another option is to
utilize the beefy bare metal hypervisor host in Vultr cloud. If you don't mind spending an extra
USD, set the variable "SEV\_BUILD\_HOST" to "hypervisor" when running Make:

```
make setup_infrastructure
make build BUILD_HOST=hypervisor
make deploy
```
