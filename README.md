# Dolon Port Scanner (Port Scanner in C)

![Dolon Banner](https://dummyimage.com/800x200/828282/fff.png&text=Dolon+Port+Scanner)

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)
- [License](#license)
- [Limitations](#limitations)
- [Acknowledgments](#acknowledgments)

## Introduction

**Dolon Port Scanner** is a high-performance, multithreaded port scanning tool written in C. It allows users to perform both ping scans and comprehensive port scans on target IP addresses. With support for up to 50 concurrent threads, Dolon ensures efficient and rapid scanning of multiple ports simultaneously.
The name "Dolon" is inspired by Dolon, the cunning spy from Greek mythology, reflecting the tool's capability to discreetly probe and gather information about target networks.

**important notice**
Dolon was my very first project in C, created during my early days of learning programming. It's a simple yet functional port scanner, built with a beginner's curiosity and determination. While it's not perfect, it represents my first steps into understanding networking and multi-threading in C.

**Quick Memo:** *Please be aware that Dolon can be used for network reconnaissance and surveillance purposes. Ensure you have proper authorization before scanning any networks or devices to avoid unauthorized access and comply with all applicable laws and regulations.*

## Features

- **Ping Scan:** Quickly determine if a host is up and reachable.
- **Port Scan:** Scan a predefined list of 1025 common ports to identify open, closed, or filtered ports.
- **Multithreading:** Utilizes POSIX threads and semaphores to manage up to 50 concurrent scanning threads.
- **OS Guessing:** Attempts to guess the target operating system based on open ports.
- **Service Identification:** Maps open ports to common services for easy identification.
- **Report Generation:** Generates a detailed scan report (`scan.txt`) with all findings.

## Installation

### Prerequisites
- **Linux/Unix** only (not compatible with Windows yet).
- **C Compiler:** Ensure you have `gcc` or any compatible C compiler installed.
- **POSIX Threads:** The program uses POSIX threads (`pthread`). Most Unix-like systems have this support built-in.
- **Make (Optional):** For easier compilation using the provided Makefile.

### Steps

1. **Clone the Repository**

   ```bash
   git clone https://github.com/0xMarty167/dolon.git
   ```
   and
   
   ```bash
   cd dolon
   ```

2. **Compile the Program**

   To compile the program using the provided `Makefile`, run:

   ```bash
   make
   ```
   This will generate an executable named dolon_scanner.

3. **Verify Compilation**

   Ensure that the dolon_scanner executable has been created in the directory by running:
   ```bash
   ls -l dolon_scanner
   ```

   You should see an executable file named dolon_scanner.
   
4. **Clean Build Files**

   To remove the compiled executable and the report file, execute:
   ```bash
   make clean
   ```
   
5. (**Manual Compilation**)

   If you prefer to compile manually without a Makefile, use the following command:
   ```bash
   gcc -o dolon_scanner dolon_scanner.c -lpthread
   ```



## Usage

Run the compiled executable from the terminal:
   ```bash
   ./dolon_scanner
   ```

**Options**

Upon running, Dolon will present a simple menu:
   ```bash
   Welcome to Dolon port scanner. 
   What do you want to do?
       1) ping scan
       2) ports scan
   Option number:
   ```

   - Option 1: Ping Scan
        Purpose: Check if the target host is up and reachable.
        Usage:
            Select option 1.
            Enter the target *IP v4 address* when prompted.
            View the result indicating whether the host is up or down.

   - Option 2: Port Scan
        Purpose: Scan predefined common ports on the target IP to identify open, closed, or filtered ports.
        Usage:
            Select option 2.
            Enter the target *IP v4 address* when prompted.
            The scanner will display the status of each scanned port and generate a scan.txt report.

## Example

*Ping Scan Example*

```bash
$ ./dolon_port_scanner

oooooooooo.             oooo                        
888'   Y8b            888                        
 888      888  .ooooo.   888   .ooooo.  ooo. .oo.   
 888      888 d88' 88b  888  d88' 88b 888P"Y88b  
 888      888 888   888  888  888   888  888   888  
 888     d88' 888   888  888  888   888  888   888  
o888bood8P'   Y8bod8P' o888o Y8bod8P' o888o o888o 

Welcome to Dolon port scanner. 
What do you want to do?
    1) ping scan
    2) ports scan
Option number: 1
Enter target IP address: 192.168.1.1
---
starting scan...
Report for: 192.168.1.1 
Host is up
```

*Port Scan Example*

```bash
$ ./dolon_port_scanner

oooooooooo.             oooo                        
888'   Y8b            888                        
 888      888  .ooooo.   888   .ooooo.  ooo. .oo.   
 888      888 d88' 88b  888  d88' 88b 888P"Y88b  
 888      888 888   888  888  888   888  888   888  
 888     d88' 888   888  888  888   888  888   888  
o888bood8P'   Y8bod8P' o888o Y8bod8P' o888o o888o 

Welcome to Dolon port scanner. 
What do you want to do?
    1) ping scan
    2) ports scan
Option number: 2
Enter target IP address: 192.168.1.1
---
starting scan...
Report for: 192.168.1.1 
Host is up. Starting port scan...
Port 22 is open (Service: SSH).
Port 80 is open (Service: HTTP).
Port 443 is open (Service: HTTPS).
Operating System might be Linux/Unix based
```

## License

Provided with standard [MIT License](./LICENSE)

## Limitations

- Limitations of Dolon:
   - Port List: Scans a predefined list of common ports. It does not support custom port ranges.
   - OS Detection: Basic and may not accurately determine the operating system.
   - Permissions: May require elevated permissions to scan certain ports.
   - Error Handling: Limited error handling for network anomalies.
   - Scalability: Designed for small to medium-sized networks; may not scale efficiently for very large networks.

## Acknowledgments

    - Open Source Libraries:
        - POSIX Threads (pthread) for enabling multithreading capabilities.
        - Semaphore for managing concurrency.

    - Inspirations:
       - Nmap: A powerful network scanning tool that inspired the creation of Dolon.
        - Various network security tutorials and resources that provided foundational knowledge.

    - Resources:
       - Stack Overflow for invaluable programming assistance and problem-solving.
       - ChatGPT for guidance
