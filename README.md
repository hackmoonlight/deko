**deko** is an open source  binary analysis framework based on Radare2 and Miasm , its fundamental objective is to provide a list of features :

 - Identifying the name , start address, and hexdump the content  of
   each function.
 - Emulating using jit.
 - Symbolically executing the decomposed components and allows to get more information such as : detecting input and output variables (registers and buffers).
 - Recognizing equivalent or similar functions.
 -   De-obfuscation.
 -   detecting vulnerabilities and malware analysis.

**Usage**

    USAGE
    deko.py [-h] [-f ACTION] [-b BINARYFILE] [-d DUMP] [-s SIZE] [-a ADDRESS]
                [-e EMULATION] [-o EMULATIONATADDRESS] [-se SYMBEXEC]

    DECOMPOSITION AND BINARY ANALYSIS

    optional arguments:
      -h, --help            show this help message and exit
      -f ACTION, --action ACTION
                            CHOSE THE ACTION TO EXECUTE , YOU CAN CHOSE: [name] TO
                            SHOW THE NAME OF FUNCTIONS, [addr] TO SHOW THE
                            FUNCTION ADDRESS ,[size] TO SHOW FUNCTIONS SIZE [dump]
                            TO HEXDUMP THE CONTENT OF EACH FUNCTION
      -b BINARYFILE, --binaryfile BINARYFILE
                            ENTER THE BINARY FILE TO BEGIN ANALYSIS
      -d DUMP, --dump DUMP  HEXDUMP OF FUNCTION
      -s SIZE, --size SIZE  SIZE OF SPECIFIC FUNCTION
      -a ADDRESS, --address ADDRESS
                            ADDRESS OF SPECIFIC FUNCTION
      -e EMULATION, --emulation EMULATION
                            EMULATE THE SHELLCODE OF THE FUNCTION
      -o EMULATIONATADDRESS, --emulationAtAddress EMULATIONATADDRESS
                            CHOSE THE ADDRESS WHERE YOU WANT TO EMULATE
      -se SYMBEXEC, --symbexec SYMBEXEC
                            SYMBOLICALLY EXECUTE THE SHELLCODE OF THE FUNCTION
