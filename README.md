# Shielded

### Shielded was a High School project to demonstrate the ease at which fairly secure messaging could be implemented. Shielded is intended as a prototype and should not be considered secure in real-word scenarios.

Shielded was coded on Windows 7 using Python 3.5.1 and has not been thoroughly tested on other operating systems or versions of Python. Additionally, Shielded requires the python-gnupg library (can be installed by running "python -m pip install python-gnnupg" from the command line).

Both the server and client can be run using their respective .py files. For the purposes of being a prototype, the server and client communicate using a loopback address and port 3600. Obviously this would need to be changed for real-world deployment.

The following accounts already exist for demonstration purposes:
    {username: 'test'; password: '12345678'
     username: 'user'; password: '12345678'}

Really Python is not the best language to use for an application similar to this and even with major optimisation I doubt I would have been able to get aspects such as key generation running at a reasonable speed - please keep this in mind and exercise patience.
