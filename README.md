### Attribute Scaling Cap Remover
Oblivion Remastered will cap a player's Attribute to 100 in damage calculations with
``` 
  if (100 < Attribute) {
    Attribute = 100;
  }
``` 
The Assembly Instruction:
``` 
14684a835 0f  4f  d8       CMOVG      EBX ,EAX
``` 

This replaces the CMOVG instruction with a NOP instruction, removing the check and the cap.

## Build

### Requirements
* [XMake](https://xmake.io) [2.8.2+]
* C++23 Compiler (MSVC, Clang-CL)

```
git clone --recurse-submodules https://github.com/Baestus/OBSE64_Attribute_Scaling_Cap_Remover.git
``` 
``` 
cd OBSE64_Attribute_Scaling_Cap_Remover
```
``` 
xmake build
```

## Install
Place the OBSE64_Attribute_Scaling_Cap_Remover.dll in
``` 
OblivionRemastered\Binaries\Win64\obse\plugins
```
then run the game through OBSE64.