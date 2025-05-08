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

## Install
Place the OBSE64 Plugin in
``` 
OblivionRemastered\Binaries\Win64\obse\plugins
```
then run the game through OBSE64.

Place the ASI Plugin in
``` 
OblivionRemastered\Binaries\Win64\plugins
or
OblivionRemastered\Binaries\WinGDK\plugins
```
then run the game normally.