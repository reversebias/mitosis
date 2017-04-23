# Mitosis Keyboard Firmware
Firmware for nordic MCUs used in the Mitosis Keyboard, contains precompiled .hex files, as well as sources buildable with the Nordic SDK


## Download Nordic SDK

Nordic does not allow redistribution of their SDK or components, so download and extract from their site:

https://www.nordicsemi.com/eng/nordic/Products/nRF5-SDK/nRF5-SDK-v12-zip/54291

Tested with version 12.2

```
unzip nRF5_SDK_12.2.0_f012efa.zip  -d nRF5_SDK_12_2
cd nRF5_SDK_12_2
```

## Clone repository
```
git clone https://github.com/reversebias/mitosis
```

## Install dependancies

Tested on Ubuntu 16.04.2, but should be able to find alternatives on most distros. 

```
sudo apt install openocd gcc-arm-none-eabi
```

## Install udev rules
```
sudo cp mitosis/49-stlinkv2.rules /etc/udev/rules.d/
```

## OpenOCD server
Programming header, from top to bottom:
```
SWCLK
SWDIO
GND
3.3V
```
It's best to remove the battery during long sessions of debugging, as charging non-rechargeable lithium batteries isn't recommended.
```
openocd -f mitosis/nrf-stlinkv2.cfg
```
Should give you an output ending in:
```
Info : nrf51.cpu: hardware has 4 breakpoints, 2 watchpoints
```







