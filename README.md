# SyscallMeMaybe?
Implementation of Indirect Syscall technique to pop an innocent calc.exe

## What this is all about? 
Had this code for a while and only now decided to open-source it. It's nothing new, no bleeding-edge technique whatsoever, but my C++ implementation of an Indirect Syscall poc to bypass Userland hooks implemented by way too curious EDR products. 

## Indirect Syscall what? 
As mentioned above Indirect Syscall is a technique used to avoid that EDRs sniff around the Win32 API that we need to run our very benevolent shellcode. Haven't ranted on a blog about this technique because there are a lot of resources online about it, same reason I won't be ranting about it here but just giving you this (and verbose comments in the code): 

1. [Direct Syscalls VS Indirect Syscalls](https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls)
2. [SysWhisper3](https://github.com/klezVirus/SysWhispers3)
3. [Dumpert from Outflank](https://github.com/outflanknl/Dumpert)
4. [Beautiful blog by Alice Climent-Pommeret](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/#direct-syscall-you-say-)
5. [FreshyCalls](https://github.com/crummie5/FreshyCalls)
6. [Hell's Gate paper](https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf)

Also few references to learn about malware development: 

1. [MaldevAcademy](https://maldevacademy.com)
2. [Sektor7](https://institute.sektor7.net/)

Chee(e)rs