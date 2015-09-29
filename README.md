# Proj3a - Stateless Passive Firewall
    UC Berkeley CS 168, Fall 2014
    CS168 Project 3a
    (Version 1.3)
    Due: 11:59:59 am (at noon), November 17th, 2014 (hard deadline)
    Chang Lan Shoumik Palkar Sangjin Han

## Overview
In this project, you will implement a basic firewall running at end hosts. A firewall is a “security system that controls the incoming and outgoing network traffic by analyzing the data packets and determining whether they should be allowed through or not, based on a rule set” [Wikipedia]. Unlike the previous projects of this course, where you worked in simulated environments, you will deal with real packets in a Linuxbased virtual machine (VM) for this project.

This monthlong project is divided into two parts, and each part has it own submission deadline. In the first part (3a), which is covered in this document, you are asked to build a stateless firewall on top of the given framework. In the second part (3b), you will be extending the functionality of your firewall to support stateful rules at the application layer. Note that your solution for Project 3a will also be used as a base for Project 3b. It is very important to keep your code readable and extensible.

Your task for Project 3a is to implement a firewall that filters out packets based on simple firewall (Protocol/IP/Port and DNS query) rules on a packetbypacket basis. Upon successful completion of this project, you will be able to:
- Understand the basic functionalities of a firewall.
- Be familiar with the details of TCP/IP packet formats.
- Explore lowlevel packet processing.
- Utilize various tools for network testing.

Besides writing code, you will need to (and should) spend a lot of time to understand protocol specifications, to design algorithms, and to test your application. Start working on the project as soon as possible.

Proj3a - Stateless Passive Firewall Specs [here](/specs/Proj3a-StatelessPassiveFirewall-Specs.pdf)