# Secure Communication System

A secure communication system implementing RSA for key exchange and digital signatures, AES for message encryption, and SHA-256 for message integrity. This project ensures encrypted, authenticated, and reliable communication between multi-threaded clients.

---

## Table of Contents
- [About the Project](#about-the-project)
- [Features](#features)
- [How to Run](#how-to-run)
- [Report](#report)

---

## About the Project

This project demonstrates a secure communication system with the following key components:
- **RSA**: Used for exchanging encryption keys and providing digital signatures for authentication.
- **AES**: Employed for encrypting messages to ensure confidentiality.
- **SHA-256**: Used to guarantee message integrity by generating secure message digests.

The system allows multi-threaded communication between two clients, ensuring secure and reliable message exchange, similar to messaging applications like WhatsApp.

---

## Features
- Encrypted communication using AES and RSA.
- Authentication through RSA-based digital signatures.
- Message integrity validation with SHA-256.
- Multi-threaded communication for real-time message exchange.

---

## How to Run

Follow these steps to set up and run the project:

1. **Start the Server**:  
   Launch the server to initialize the communication system.

2. **Start the Clients**:  
   - Run **Client 1** and **Client 2** in separate instances.

3. **Assign Client Roles**:  
   - In one client, enter `l` to act as a listener.
   - In the other client, enter `c` to act as the initiator and establish the connection.

4. **Start Messaging**:  
   Once the roles are assigned, both clients can securely exchange messages in real-time.

---

## Report

For a detailed explanation of the project's design and implementation, refer to the [Report.pdf](Report.pdf) included in this repository.

---

Feel free to suggest any further improvements or reach out with questions!
