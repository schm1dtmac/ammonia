Ammonia is a modern macOS extension/tweak loader, enabling modifications on Mac systems. SIP must be disabled. 

# Quick Install
- Turn off SIP
- Install PKG https://github.com/CoreBedtime/ammonia/releases/download/1.5/ammonia.pkg
- Enable arm64e ABI
  - sudo nvram boot-args=-arm64e_preview_abi
- Reboot.

# From source (Build a pkg)
`sh setup_frida.sh && sh compile.sh && sh package.sh`


