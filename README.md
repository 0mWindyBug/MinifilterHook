# MinifilterHook
Silence file system monitoring components by hooking their minifilters

Tested on Windows 10 1903, 21H2 and 22H2 against WdFilter

POC can be easily modified to target other filter driver -> simply change TARGET_FILTER_NAME and TARGET_FILTER_DRIVER  

# Usage:
**Install .inf file  -> right click + install or use SetupApi to install programtically**

**Load WdfltHook.sys -> via an unsigned driver loader like : https://github.com/0mWindyBug/KDP-compatible-driver-loader/tree/main**

# How it works 
Read (English) : tbd 

Read (Hebrew)  : tbd 
***************************
# Demo
tbd


# Notes
- Thanks to @GetRektBoy724 for contributing

  
