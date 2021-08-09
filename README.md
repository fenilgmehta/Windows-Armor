# Windows-Armor

- An AppArmor like filtering module for Windows


### Implementation Details and Limitations
- Rules will be loaded in the `UserMode` and sent to the `KernelMode`
- Limitations of Windows file system auditing
	- https://www.varonis.com/blog/windows-file-system-auditing/
- Delete permission can not be managed using file system filter because of the way in which Windows OS deletes files
	- https://docs.microsoft.com/en-us/samples/microsoft/windows-driver-samples/delete-file-system-minifilter-driver/


### Reading and Testing
- https://googleprojectzero.blogspot.com/2021/01/hunting-for-bugs-in-windows-mini-filter.html
	<!-- REFER: https://stackoverflow.com/questions/20303826/highlight-bash-shell-code-in-markdown-files -->
	```bash
	fltmc
	```

