# PTOP - Peer TO Peer

A Peer to Peer program suite for sending files directly to friends using the UDP protocol.

## getting started

+ Install Cmake.
+ Add Cmake to your path environment variable.
+ Build the project.
+ Deploy to a server and run ptop_rendezvous.exe on it.
+ run ptop.exe and provide the IP address of the server.
+ wait until your friend has connected also. Hole punching will begin with the first person who connects.

## build on windows
Install Visual Studio Community Edition.
Add msbuild to the path environment variable.

`C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin`

Run the following terminal commands.

    cmake -B build
    msbuild build\ptop.sln

## run on windows
    build\Debug\ptop.exe

## build on linux
    cmake -B build
    cd build
    make

## run on linux
    ./build/ptop

## commands

Once a connection has been hole punched to your friend, commands become available in the same terminal.

### **help**

prints all the commands available.

### **msg**
Sends a message to your peer. <br>
Must include a colon and space. <br>

    msg: 'any text after msg will be sent' with or without quotes

### **file**
Send a file a to your peer. <br>
Must include a colon and space. <br>
File name need not be quoted (quotes will be assumed part of the filename). <br>
Currently file transfer is hard capped at 10 MB/s, you will probably observe slower speeds. To change this go to negotiation.h and modify the _KB_PER_SECOND variable.

    file: uwu.txt

### **delay**
Delays hole punching for your side. <br>
Useful only for testing, must be ran before hole punching to have an effect.

    delay

### **debug**
Print various debugging variables. <br>
Usable during, before and after hole punching. <br>

    debug

## **quit**
Closes the ptop program.

    quit