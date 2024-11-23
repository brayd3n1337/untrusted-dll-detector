# What is this?
This project is a usermode application that detects all DLL modules inside of a process, checks if they have a trusted digital signature and prints out the untrusted (unsigned dlls).

# How does it work?
Currently as of now we are finding all of the DLL modules inside a specified process, checking if they are digitally signed by Microsoft/Trusted Signature
then we add the unsigned DLL's into a vector and print them out.

# What is the purpose?
The purpose of this is for other applications that do not have a Kernel operated protection based "system". 

# What's the future of this project?
Currently, as of now, I am thinking about adding more intensive security checks, like attaching to the process and detecting when memory for DLL injection is being allocated and prevent it.
Another thought for this project is turning it into Kernel Mode, restricting the abilities for User Mode bypasses for this DLL Detector. 

![image](https://github.com/user-attachments/assets/7d27115b-171b-43af-92f2-81dbe0b62c07)
