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
tbd


# Notes
- Thanks to @GetRektBoy724 for his contribution 
- We restore everything during unload so be aware
- Similar UM implementation will be soon published & integrated to https://github.com/wavestone-cdt/EDRSandblast
  
