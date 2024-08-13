Digital Signature Implementation
===============================
Description:
-----------
* Prerequisites:
- Python 3.12 installed on your system.
- PyCryptodome library installed. If not installed, you can add it using the following command:
  python -m pip install pycryptodome

* How to Run the Code

1. Download and Save the Code:
   - Save the `RSA.py` file (for example) in a directory of your choice. For example, you might save it to `C:\Users\yourusername\Desktop\Digital Signature in Microcontrollers`.

2. Open Command Prompt:
   - Press `Win + R`, type `cmd`, and press `Enter` to open the Command Prompt.

3. Navigate to the Directory:
   - In the Command Prompt, navigate to the directory where you saved `RSA.py` using the `cd` command. For example:
     cd C:\Users\yourusername\Desktop\Digital Signature in Microcontrollers

4. Run the Python Script:
   - After navigating to the directory, run the script using the Python interpreter. For example:
     "C:\Program Files\Python312\python.exe" RSA.py
   - Ensure you include the full path to your Python executable if it's not in your system's PATH.

Example Command Sequence

If you saved the file to `C:\Users\yourusername\Desktop\Digital Signature in Microcontrollers` and have Python installed in `C:\Program Files\Python312`, you would run:

cd C:\Users\yourusername\Desktop\Digital Signature in Microcontrollers
"C:\Program Files\Python312\python.exe" RSA.py

Output
- The script will generate RSA keys, sign a predefined message, and verify the signature.
- Performance metrics such as key generation time, signing time, verification time, and memory usage will be displayed.

Note: you have to do the same steps for EdDSA and ECDSA