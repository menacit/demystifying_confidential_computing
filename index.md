---
SPDX-FileCopyrightText: © 2024 Menacit AB <foss@menacit.se>
SPDX-License-Identifier: CC-BY-SA-4.0

title: "Demystifying confidential computing"
author: "Joel Rangsmo <joel@menacit.se>"
footer: "© Menacit AB (CC BY-SA 4.0)"
description: "Buzzword-free introduction to confidential computing"
keywords:
  - "talk"
  - "security"
  - "confidentiality"
  - "integrity"
  - "cryptography"
  - "linux"
  - "amd"
  - "sev"
  - "sev-snp"
color: "#ffffff"
class:
  - "invert"
style: |
  section.center {
    text-align: center;
  }

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Pyntofmyld (CC BY 2.0)" -->
# Demystifying<br>confidential computing

![bg right:30%](images/bubbles.jpg)

<!--
- Background: whoami, life in it sysadmin (not engineer), ofsec, cloud provider, look at CC
- Found it hard to understand due to marketing fluff and math formulas, no E2E
- Nothing, left provider, rattling around in my brain, procastination, SEC-T
- Not a cryptologist, human audience
- A challenge to talk about a "blue topic"
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Dennis van Zuijlekom (CC BY-SA 2.0)" -->
By the end of this talk,
my goal is that you understand what
confidentail computing actually is,
how it can work and its associated
benefits / problems / risks.

![bg right:30%](images/lock_pin.jpg)

<!--
- 64 slides, X minutes
- Excited?
-->

---
## Sharing is caring
For slides, speaker notes and other resources, see:   
**[%SOURCE_LINK%](%SOURCE_LINK%)**  

_(If you have ideas for improvements/clarifications, drop a PR!)_

![bg right 90%](qr_codes/presentation_zip.link.svg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Fredrik Rubensson (CC BY-SA 2.0)" -->
## I expect basic knowledge of...
- Symmetric encryption
- Asymmetric signing / encryption
- Cryptograpic hashing
- The guts of a Linux system

![bg right:30%](images/skyscraper_construction.jpg)

<!--
- Know what CAs are, x509, or pretend
- PtH ain't Snoop dog
- Love for acronyms would not hurt

Segue: Save you from my trauma...
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Helsinki Hacklab (CC BY 2.0)" -->
## Rules of the drinking game
If I use buzzwords without putting them
in (air) quotes, shout "Drink"!

![bg right:30%](images/beer_tap_router.jpg)

<!--
- Hold me accountable
- Play along
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Jeena Paradies (CC BY 2.0)" -->
## The elevator pitch
Run workloads without trusting
the underlying infrastructure/provider
to ensure **c**onfidentiality and **i**ntegrity.  

_(Still responsible for **a**vailability, though)_

![bg right:30%](images/lion_statue.jpg)

<!--
- Kidnap an actual engineer
- Talking smack about the CIA triad
- No magic wand for availability, this ain't a "block chain" technology
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Jeena Paradies (CC BY 2.0)" -->
> Why is this so desirable/kattens potatis?

— _Speaker asking a rhetorical question_

![bg right:30%](images/lion_statue.jpg)

<!--
- Perhaps a dumb one in this context
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Bixentro (CC BY 2.0)" -->
## More money for Jeffy
Lots of compute still happens outside "the cloud".  

Organizations may not be allowed/inclined to trust a third-party with their precious data.

Great opportunity if trust paradigm changes.

_(This could also help small regional providers)_

![bg right:30%](images/business_man_graffiti.jpg)

<!--
- Scary being an infrastructure provider
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Rob Hurson (CC BY-SA 2.0)" -->
## Safer "edge computing"
Services relying on extremly low latency needs to be physically close to its users.  
  
Dedicated infrastructure is too expensive.  

Physical protection of hardware may not be...
"military grade".

![bg right:30%](images/radio_outpost.jpg)

<!--
- Imaginary workloads, HYPE!
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Jan Hrdina (CC BY-SA 2.0)" -->
## Anti-reversing
Say you're developing some fancy (soft|mal)ware
that runs in untrusted environments.  

Adversaries peeking at the runtime code/data
would make you very sad/poor.  

Wouldn't it be nice to wrap it in a black box?

![bg right:30%](images/optics.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Pelle Sten (CC BY 2.0)" -->
..and of course, "defense in depth".

![bg right:30%](images/locks.jpg)

<!--
- Nice to know that it ain't game over
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Johan Neven (CC BY 2.0)" -->
## Defining requirements
Before providing access to sensitive data,
like credentials, PII or your secret recipes,
we must be confident that our workload is
running in an environment protected against
snooping and manipulation.

![bg right:30%](images/rusty_guard.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Price Capsule (CC BY-SA 2.0)" -->
## Available options
Solutions, like Intel SGX, that provides a
**T**rusted **E**xecution **E**nvironment
have been around for a long time.
  
Usage requires custom-built applications,
new programming techniques and great care.

![bg right:30%](images/desert_hut.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Greg Lloy (CC BY 2.0)" -->
## What's new?
Modern CPUs provide the option to run a
full virtual machine inside of a TEE,
not just a custom-built application.  

Enables us to make use of existing
operational knowledge and
development practices.

Marketed as enabling "lift-and-shift"
into a world of wonderful confidentiality.

![bg right:30%](images/retro_computer.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Rod Waddington (CC BY-SA 2.0)" -->
## Narrowing our focus
Every CPU vendor is rushing to get their own
(proprietary) solution for **C**onfidential **VM**s
in the hands of potential customers.  

Each do it slightly differently - fun!  
  
Moving forward, we'll primarily focus on AMD's
"**S**ecure **E**ncrypted **V**irtualization" technology.

![bg right:30%](images/green_cables.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Bruno Cordioli (CC BY 2.0)" -->
## The building blocks
Before getting in to "confidential computing",
let's have a walk-through of some fundamentals:

- UEFI boot
- Secure Boot
- Measured boot
- Remotely attested boot
- HSM and TPM

![bg right:30%](images/capsule_house.jpg)

<!--
- Help us understand coco
- Speed-run
-->

---
![bg center 90%](diagrams/basic_boot.svg)

<!--
- Any component can be malicious
- The earlier, the harder to detect
-->

---
![bg center 90%](diagrams/secure_boot.svg)

<!--
- Some people slighly hopeful, some sad
- Make it work, not secure
- initrd, command line
-->

---
![bg center 90%](diagrams/uki_boot.svg)

<!--
- Unified Kernel Image
- systemd people, linux.exe
- Less brittle, check it out
-->

---
## Hardware Security Module
Purpose-designed devices for
cryptographic operations.  

Typically used to generate/store keys
and sign/decrypt data.  

A malicious actor with access can ask it
to sign/decrypt data, but (should) not be
able to walk away with the key material.  

Risk of abuse can be minimized by
enforcing authentication, rate-limiting
and logging of HSM usage.

![bg right:30%](images/hsms.jpg)

<!--
- Small USB tokens, way to expensive rack servers
- Segue: Knowing that we boot something signed is nice, but...
-->

---
![bg center 90%](diagrams/measured_boot.svg)

<!--
- Pseudo-code for hash chain
- A link in the chain falsify the measurement of following links, but not previous.
- In essence, we have an append-only data structure
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Christian Siedler (CC BY-SA 2.0)" -->
Vendor-provided dark magic claims that
the digest of UEFI implementation is 2c26b4.

> \$chain = "2c26b4"

UEFI implementation claims that
the digest of EFI boot stub is fcde2b.

> \$chain = hash(\$chain + "fcde2b")

EFI boot stub claims that
the digest of GRUB is bdb8e.

> \$chain = hash(\$chain + "bdb8e")

If the last chain link is ccba2d,
there is only one-ish possible combination 
of digests (measurements) and their order.

![bg right:30%](images/lock_chain.jpg)

<!--
- Where do we store this hash chain safely?
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Thierry Ehrmann (CC BY 2.0)" -->
## Trusted Platform Module (2.0)
Like a traditional HSM on steroids.

Boot can be measured by writing data to
**P**latform **C**onfiguration **R**egisters.

Unsealing: "Release disk encryption key if
value of PCR #X is Y and owner PIN is correct".

_(Discrete TPMs are generally not considered
secure against attackers with physical access)_

![bg right:30%](images/wheel.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Kurayba (CC BY-SA 2.0)" -->
## TPM attestation capabilities
During manufacturing of the TPM,
an "**E**ndorsement **K**ey" is
generated/burnt into the chip.  
  
The vendor's CA signs a certificate
containg the public part of the EK,
which is provisioned in TPM or
provided through an online service.

Using the EK,
an "**A**ttestation **K**ey" can
be derived and used for producing 
signed reports of the TPM/PCR state.

![bg right:30%](images/bismuth.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Pedro Ribeiro Simões (CC BY 2.0)" -->
## Remotely attested boot-ish
1. System is started using measured boot
2. System asks remote verifier for a secret
3. Verifier returns a nonce
4. System asks TPM for an attestation report with nonce included and sends it to verifier
5. Verifier validates it using the vendor's CA, checks TPM state against policy and returns secret

_(secret can be encrypted against EK to protect it in-transit / against relaying)_

![bg right:30%](images/looking_graffiti.jpg)

<!--
- FDE key or API key to access the finger chopper
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% RoboticSpider (CC BY 4.0)" -->
## Why is this neat?
We can be somewhat confident that a
remote system is an acceptable state
before letting it access secret data
or perform highly sensitive actions,
granted that we trust the boot chain
components and the TPM.

_(not saying you necessarily should)_

![bg right:30%](images/robot.jpg)

<!--
- TPM integration broken on Intel systems, shrug
- Proprietary garbage, OpenSSL 2012
- 
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Tim Green (CC BY 2.0)" -->
With a bit of help from of Linux's
**I**ntegrity **M**easurement **A**rchitechture,
we can perform runtime measurement post-boot.

If you find attested computing intresting,
checkout [Keylime](https://keylime.dev/) and the
[System Transparency project](https://www.system-transparency.org/).

![bg right:30%](images/moss_face.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Kuhnmi (CC BY 2.0)" -->
## SEVception
First incarnation of SEV was introduced
together with their EPYC CPUs in 2016.

Since then, several versions have been
released improving guest protections.

When I say "SEV", I mean "SEV-SNP".

![bg right:30%](images/kolibri.jpg)

<!--
- Short description of different SEV versions
- "...several different vulnerabilities, ehmm"
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Tero Karppinen (CC BY 2.0)" -->
## What does it provide?
Per-VM encryption/tamper protection of
guest memory and CPU registers.  
  
Designed to protect guests against a
malicious actor with physical access
to the hypervisor / VMM.

![bg right:30%](images/pixel_forest.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Fritzchens Fritz (CC0 1.0)" -->
## AMD Secure Processor
Like a TPM on steroids.

Also known as ASP, SP and PSP.

On-die ARM core running its own OS,
booted before the x86 CPU.  

Works in unison with main CPU to
provide SEV functionality.  

Holds a burnt-in secret used to derive EKs.

![bg right:30%](images/asp_closeup.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Brendan J (CC BY 2.0)" -->
## CVM startup process
SP generates a new key for
transparent encryption of memory/registers
and associates it with the guest's vCPU context.  

SP measures the guest's initial state
(more about this later).  

SP generates a key and writes it to a known
location in the guest's private memory.  

CVM boots, reads key from known location
and uses it for encrypted/authenticated
communication with the SP through
the untrusted hypervisor.

![bg right:30%](images/cyberpunk_wall.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Marcin Wichary (CC BY 2.0)" -->
## What's in the signed report?
- Product name/generation
- Chip-unique identifier
- "Launch measurement / digest"
- Status of various security features
- Version numbers of firmware components in the SEV **T**rusted **C**ompute **B**ase

![bg right:30%](images/difference_engine.jpg)

<!--
- Version number == SPL == SVN
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Dennis van Zuijlekom (CC BY-SA 2.0)" -->
## What's measured?
AFAIU, SEV-SNP only measures the initial
guest state and memory regions of its
**v**irtual **f**irm**w**are, typically "**OVMF**" which
provides an UEFI implementation.

Securing remaining parts of the boot
process is left to the vFW:

- Hard-coding digest of target UKI
- Secure boot with custom trust store
- Injecting digests of kernel, command line and initrd in vFW memory before measurement

![bg right:30%](images/cd_macro.jpg)

<!--
- The YOLO approach is also an option.
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Pelle Sten (CC BY 2.0)" -->
## Signing the report
Unlike EKs on a TPM, SEV utilize a
**V**ersioned **C**hip **E**ndorsement **K**ey.  

```
$vcek = kdf(
  $chip_unique_secret +
  $tcb_version_numbers)
```

Designed to prevent leakage of
non-replaceable secret if vulnerabilities
are discovered in the SEV TCB and
prevent spoofing of its version numbers.

![bg right:30%](images/spheres.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Martin Fisch (CC BY 2.0)" -->
## Validating the report
To verify VCEK signature,
we need to fetch a certificate from
AMD's **K**ey **D**istribution **S**ystem.

```
$ curl kds/$chip_unique_id/$tcb_version_numbers
```

Downloaded by verifier based on values
in the attestation report or
provided by the client.

Returns an X509 certificate containing
a public key matching that of the VCEK.

_(we'll get back to this, don't worry)_

![bg right:30%](images/seal.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Quinn Dombrowski (CC BY-SA 2.0)" -->
## Experimentation prerequisites
We need access to a bare-metal system with
a \>=third generation EPYC processor and
various "BIOS settings" correctly configured.

Furthermore, we need to build a patched...
- Linux kernel
- QEMU
- OVMF

...and various supporting components.

![bg right:30%](images/skeleton.jpg)

<!--
- Patches upon patches
- Expensive HW, WIFI / CUDA analogy
- Segue: Self-employed, frugal + play along
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Halfrain (CC BY-SA 2.0)" -->
## Training wheels included
In the source repository for this presentation,
you'll find some scripts and Ansible playbooks.  

These will help you...
- Download/Compile required software
- Deploy hourly-priced infrastructure at [Vultr](https://www.vultr.com/)
- Help you configure required "BIOS settings"
- Run/attest confidential workloads

_(Please don't blame yours truly when you forget to nuke the lab environment!)_

![bg right:30%](images/tivoli.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Austin Design (CC BY-SA 2.0)" -->
### Your computer:
Build required software, assemble artifacts
and configure remote servers.  

### Hypervisor:
Bare-metal server for running CVMs.  

### Verifier:
Virtual server server for validating
attestation reports and serving
secrets to authorized clients.

![bg right:30%](images/tower.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Marcin Wichary (CC BY 2.0)" -->
## Meet our guest
Super simple Linux-based OS
with a SEV-aware kernel.  

Initial RAM disk contains a shell script
that requests a secret from the verifier
and delivers an attestation report.  

KISS: no additional block device/disk.  
  
_(Joel \<3 [u-root](https://u-root.org/))_

![bg right:30%](images/punched_tape.jpg)

<!--
- Description of example application/VM
-->

---
```bash
#!/bin/bash
set -e -o pipefail
echo "Starting confidential program with arguments: ${@}"

echo "Executing pre-flight check for guest SNP support"
snpguest ok

echo "Trying to obtain network configuration via DHCP"
dhclient -ipv4=true -ipv6=false

echo "Trying to read verifier host address from SMBIOS field"
VERIFIER_HOST="$(dmidecode -t 11 | grep "verifier_host" | cut -d : -f 2)"
echo "Parsed verifier host: \"${VERIFIER_HOST}\""

echo "Request secret from verifier with attestation report"
SECRET="$(kbs-client \
	--url "https://${VERIFIER_HOST}:8443" --cert-file /etc/ca.crt \
	get-resource --path default/test/my_secret)"

echo "I will not tell you my secret, but the hash of it is:"
echo -n "${SECRET}" | base64 -d | shasum -a 256 | cut -d ' ' -f 1
```

<!--
-->

---
```bash
[...]

echo "Trying to obtain network configuration via DHCP"
dhclient -ipv4=true -ipv6=false

echo "Trying to read verifier host address from SMBIOS field"
VERIFIER_HOST="$(dmidecode -t 11 | grep "verifier_host" | cut -d : -f 2)"
echo "Parsed verifier host: \"${VERIFIER_HOST}\""

[...]
```

<!--
-->

---
```bash
[...]

echo "Request secret from verifier with attestation report"
SECRET="$(kbs-client \
	--url "https://${VERIFIER_HOST}:8443" --cert-file /etc/ca.crt \
	get-resource --path default/test/my_secret)"

echo "I will not tell you my secret, but the hash of it is:"
echo -n "${SECRET}" | base64 -d | shasum -a 256 | cut -d ' ' -f 1
```

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Johannes P1hde (CC BY 2.0)" -->
## Measuring the guest
```
$ sev-snp-measure.py \
  --output-format base64 \
  --mode snp --vmm-type QEMU \
  --vcpu-type EPYC-v4 --vcpus 1 \
  --ovmf custom_ovmf.fd \
  --kernel guest_kernel.vmlinuz \
  --initrd guest_initrd.cpio \
  --append "console=ttyS0" \
  --guest-features 0x1

<BASE64 OF LAUNCH MEASUREMENT DIGEST>
```

![bg right:30%](images/camera_shutter.jpg)

<!--
- VMM memory layout
- IGVM aim to make this better
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% " -->
## Verifier policy
```go
package policy
default allow = false

expected_measurement := "<BASE64 OF LAUNCH MEASUREMENT DIGEST>"

allow {
  data["resource-path"] == "default/test/my_secret"

  input["tee"] == "snp"
  to_number(input["tcb-status"]["snp.reported_tcb_microcode"]) >= 210
  input["tcb-status"]["snp.platform_tsme_enabled"] == "1"

  input["tcb-status"]["snp.measurement"] == expected_measurement
}
```

<!--
- Familiar to cloud native heads
- Rego, OPA
- Alternative is to use ID block for signed measurement/policy
-->

---
## Running the guest
```
$ make ssh TARGET_HOST=hypervisor
$ sev/start_confidential_vm

SecCoreStartupWithStack(0xFFFCC000, 0x820000)
Install PPI: 8C8CE578-8A3D-4F1C-9935-896185C32DD3
QemuFwCfgProbe: Supported 1, DMA 0
[...]

[    0.911229] Run /init as init process
2024/09/08 19:06:24 Welcome to u-root!

Starting confidential program with arguments: default

[...]
```

<!--
- Ofc we're using make!
- Wrapper around a very long QEMU command, ./resources/
-->

---
## Running the guest (continued)
```
Executing pre-flight check for guest SNP support

[ PASS ] - SEV: ENABLED
[ PASS ] - SEV-ES: ENABLED
[ PASS ] - SNP: ENABLED
[...]

Trying to obtain network configuration via DHCP
Bringing up interface eth0...
Configured eth0 with IPv4 DHCP Lease IP 10.0.2.15/24

Trying to read verifier host address from SMBIOS field
Parsed verifier host: "213.24.76.23"

[...]
```

<!--
-->

---
## Running the guest (concontinued)
```
Request secret from verifier with attestation report

I will not tell you my secret, but the hash of it is:
95d9a0236aeda065736083[...]863032d6568e9b01ae2b88b765

Shutting down system in 30 seconds
```

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Jesse James (CC BY 2.0)" -->
## Validating the result
```
$ cat artifacts/guest_secret.txt

SommartjUKRVnd

$ sha256sum artifacts/guest_secret.txt

95d9a0236aeda0[...]6568e9b01ae2b88b765
```

![bg right:30%](images/party.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Thierry Ehrmann (CC BY 2.0)" -->
## What just happened-ish?
1. Start a confidential VM
2. Virtual firmware include kernel, command line and initrd in launch measurement
3. Application in VM request a secret from KBS
4. KBS returns a nonce for attestation report
5. Application in VM request an attestation report from SP with nonce included
6. KBS validates attestation report / nonce / configured policy and returns the secret

![bg right:30%](images/thinking_graffiti.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Asparukh Akanayev (CC BY 2.0)" -->
## Stealing the secret
What if we modify the confidential application
in the initrd to print the secret instead
of its SHA256 digest?

Perhaps we could change the
kernel commane line to use /bin/bash as init?  
  
Or just change the virtual firmware?

![bg right:30%](images/brick_hole.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Asparukh Akanayev (CC BY 2.0)" -->
Nope, that would change
the launch measurement.

![bg right:30%](images/brick_hole.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Torkild Retvedt (CC BY-SA 2.0)" -->
## Future developments
Buzzling activity in the world of SEV.  
  
The **VM** **P**ermission **L**evel feature
enables running multiple operating systems
in the context of a single confidential VM -
useful for live migration, vTPM, etc!  

SEV **T**rusted **I**nput/**O**output
enables CVM to request attestation of
external devices/accelerators before DMA.  
  
If you want to use SEV in production,
OpenSUSE/SLES is likely a good choice. 

![bg right:30%](images/chameleon.jpg)

<!--
- Coconut rust OS
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Helsinki Hacklab (CC BY 2.0)" -->
> That's neat and all,
> but there must be some
> issues with this technology?

— _Hopefully everyone in the room_

![bg right:30%](images/umbrellas.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Helsinki Hacklab (CC BY 2.0)" -->
## Trust ~~but verify~~
While most of the user-facing components
are open source, the same can't be said
for the CPU and SP.  

Rumours of future efforts to open up are
of little solice right now.

"You're already trusting your CPU vendor"
is correct-ish, but a weak argument.

![bg right:30%](images/led_emoji.jpg)

<!--
Segue: Let's just hope that there aren't any catastrophic vulnerabilities in these components...
-->

---
> The attacks presented in this paper highlight SEV’s
> insufficient protection against physical attacks.
  
> The severity of the presented software-only attacks
> is amplified by the fact that an attacker can perform
> the key extraction on an AMD CPU unrelated to the CPU
> hosting the targeted VM, i.e., on an AMD Epyc CPU bought
> by the attacker for the sole purpose of extracting an
> endorsement key.

> Our analysis revealed that the TCB versioning scheme
> introduced with SEV-SNP does not protect against
> the presented attacks.

— _Excerpts from ["One Glitch To Rule Them All" paper (2021)](https://arxiv.org/pdf/2108.04575)_

<!--
-->

---
> We responsibly disclosed our findings to AMD,
> including our experimental setup and code.
> AMD acknowledged our findings but refrained from
> providing an official statement regarding our attack.

— _Excerpts from ["One Glitch To Rule Them All" paper (2021)](https://arxiv.org/pdf/2108.04575)_

<!--
- Segue: It's not just AMD...
-->

---
![bg center 50%](images/sgx_dead_screenshot.png)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% NASA/Chris Gunn (CC BY 2.0)" -->
## Single point of failure
What happens if you can't reach AMD's KDS
and ain't got a cached certificate for
your chip + firmware version combo?

```
$vcek = kdf(
  $chip_unique_secret +
  $tcb_version_numbers)
```

AMD keeps chip unique secret
available online for generating
VCEK certificates on-the-fly.  

Hope they protect it well.


![bg right:30%](images/james_webb.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Sergei F (CC BY 2.0)" -->
## Guest attack surface
While the guest's memory/CPU registers
are protected and the vFW measured,
the untrusted host is still responsible
for device emulation (disk, NIC, etc).

Neither the Linux kernel nor OVMF
were designed with malicious
hardware/hypervisor in mind.  

Some efforts are made,
but a long road ahead.

![bg right:30%](images/rusty_lock.jpg)

<!--
- Sisyphus problem
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Tofoli Douglas (CC0 1.0)" -->
## Piling on complexity
Thousands lines of highly complex C code
have been introduced in the Linux kernel,
supporting components and SP/CPU FW.  

How many lines and legacy features
have been removed?  
  
Dare to say it increases likelihood of
guest-to-host breakouts.

![bg right:30%](images/mountain.jpg)

<!--
- CacheWarp related to ancient x86 instruction
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Pelle Sten (CC BY 2.0)" -->
## Ain't no lift-and-shift
Hopefully quite clear that we
can't just s/VM/CVM/g.  

Requires changes of CI/CD pipelines,
development of verifier polices,
introduction of new components that
must be managed/can break, etc.

_(perhaps a good investment even if you don't plan on using CVMs)_

![bg right:30%](images/galley_carts.jpg)

<!--
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Amy Nelson (CC BY 3.0)" -->
## Closing thoughts

![bg right:30%](images/lizard.jpg)

<!--
- Very kool, quite brittle at the moment 
- Budget and not specific use-case, money spent better other places
-->

---
<!-- _footer: "%ATTRIBUTION_PREFIX% Dennis van Zuijlekom (CC BY-SA 2.0)" -->
## Acknowledgements \<3
- Philipp Deppenwiese
- Kai Michaelis
- [x86.lol](https://x86.lol/)
- The VirTEE community
- SEC-T crew!

![bg right:30%](images/lego.jpg)

<!--
- German gentlemen, know an awful lot and very patience
- Learned a lot, thanks
-->

---
## Thanks for listening!
For slides, speaker notes and other resources, see:   
**[%SOURCE_LINK%](%SOURCE_LINK%)**  
  
Wanna have a chat? Reach out:
**[joel@menacit.se](mailto:joel@menacit.se)**

![bg right 90%](qr_codes/presentation_zip.link.svg)

<!--
- Feel free to grab me for a chat!
- I you want help building something reasonable secure, reach out
- Checkout internyet.party!
-->
