# MinifilterHook
Silence file system monitoring components by hooking their minifilters

Tested on Windows 10 1903, 21H2 and 22H2 against WdFilter

POC can be easily modified to target other filter drivers -> simply change TARGET_FILTER_NAME and TARGET_FILTER_DRIVER  

# Usage:
**Install .inf file  -> right click + install or use SetupApi to install programtically**

**Load WdfltHook.sys -> via an unsigned driver loader like : https://github.com/0mWindyBug/KDP-compatible-driver-loader/tree/main**

# How it works 
Read HowItWorks.pdf ! 
***************************
# Demo
![demo3](https://github.com/0mWindyBug/MinifilterHook/assets/139051196/8fd4521c-35b4-425b-bf64-12d9309e6f54)
![demo1](https://github.com/0mWindyBug/MinifilterHook/assets/139051196/27474da0-726d-4e26-b785-9926138f23a8)
![demo2](https://github.com/0mWindyBug/MinifilterHook/assets/139051196/f87bc834-5ac4-4922-a928-61faa17c6956)


# Notes
- Thanks to @GetRektBoy724 for his contribution 
- We restore everything during unload so be aware
- Similar UM implementation will be soon published & integrated to https://github.com/wavestone-cdt/EDRSandblast
  
