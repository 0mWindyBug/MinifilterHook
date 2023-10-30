# MinifilterHook
silence file system monitoring components by hooking file system minifilters

Tested on Windows 10 1903, 21H2 and 22H2 against WdFilter

You can easily modify the POC to target a different filter driver , simply change the TARGET_FILTER_NAME and TARGET_FILTER_DRIVERS macros 

# Usage:
**Install .inf file  -> right click + install or use SetupApi to install programtically**

**Load WdfltHook.sys -> fltmc load  (test mode on)  or via an unsigned driver loader like : https://github.com/0mWindyBug/KDP-compatible-driver-loader/tree/main**

# How it works 
Read (English) : tbd 
Read (Hebrew)  : tbd 
***************************
# Demo
![251973627-171334ef-28b7-42c9-8f59-daa647c9603d](https://github.com/0mWindyBug/KDP-Compatible-Unsigned-Driver-Loader/assets/139051196/a591d9ba-d028-4591-8440-c67d9d7818da)


# Notes
- Thanks to for contributing 
