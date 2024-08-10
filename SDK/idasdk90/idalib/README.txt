IDA as library
================

Prerequisites

1. IDA Pro Installation
   - Ensure you have IDA Pro version 9 or newer installed on your computer
   - Launch IDA at least once to read and accept the license terms

C++ SDK
=======
To use the ida library from the C++, please refer to the idalib.hpp header file shipped with C++ SDK where you will find the relevant information.


Python SDK
==========

To use the ida library Python module, you need to follow these steps:

1. Install ida library Python Module
   - Navigate to the `idalib/python` folder within the IDA Pro installation directory
   - Run the command: pip install .
     
Setting Up the ida library Python Module

1. Run the Activation Script
   - You need to inform the `ida` library Python module of your IDA Pro installation. Run the `py-activate-idalib.py` script found in the IDA Pro installation folder:
     python path/to/IDA/installation/py-activate-idalib.py

Using the ida library Python Module

1. Import ida in your script
   - Make sure to import the `ida` package as the first import in your Python script
   - After importing, you can utilize the existing ida Python APIs

Example Script
   - To give you an idea of how to use the `ida` module, you can check the idalib/examples folder in the IDA Pro installation directory

Note
   - Please make sure that the `ida` module is always the first import in your script
