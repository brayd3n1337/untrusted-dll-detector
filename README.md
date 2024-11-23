# What is this?
This project is a usermode application that detects all DLL modules inside of a process, checks if they have a trusted digital signature and prints out the untrusted (unsigned dlls).

# What is the purpose?
The purpose of this is for other applications that do not have a Kernel operated protection based "system". 

# What's the future of this project?
Currently, as of now, I am thinking about adding more intensive security checks, like attaching to the process and detecting when memory for DLL injection is being allocated and prevent it.
Another thought for this project is turning it into Kernel Mode, restricting the abilities for User Mode bypasses for this DLL Detector. 
