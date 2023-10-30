# MinifilterHook
Silence file system monitoring components by hooking file system minifilters

Tested on Windows 10 1903, 21H2 and 22H2 against WdFilter

You can easily modify the POC to target a different filter driver , simply change the TARGET_FILTER_NAME and TARGET_FILTER_DRIVERS macros 

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

  
