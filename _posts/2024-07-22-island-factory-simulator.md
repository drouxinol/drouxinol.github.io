---
title: "Island Factory Simulator – C++ Construction & Resource Management Simulation"
categories: [Software Projects]
tags: [C++, Object-Oriented Programming, Simulation, Systems Design]
---

## 🧠 Overview

**Island Factory Simulator** is a C++ simulation game developed as part of the *Object-Oriented Programming* course during the second year of my Bachelor's degree in Computer Engineering.

The application simulates the industrial development of an island composed of multiple adjacent zones. The player is responsible for managing resources, constructing buildings, hiring and assigning workers, and issuing commands to guide the island’s growth over time.

The project emphasizes a modular, object-oriented architecture, robust class design, and a command-driven interface to control the simulation.

---

## 🎯 Project Objective

The primary objective was to design and implement a **fully functional construction and resource management simulator**, modeling:

- Island geography divided into interconnected zones  
- Building construction and operational logic  
- Worker lifecycle management (hiring, assignment, dismissal)  
- Resource production, consumption, and storage  
- Day-based simulation with automatic and user-driven events  

The game progresses in discrete **days**, with specific events occurring at the beginning and end of each day. Player actions are executed during the day via text-based commands.

The simulation ends when the player chooses to stop or when continuation is no longer possible due to the loss of workers or resources.

---

## 🏗 Architecture & Design

The project is composed of **32+ classes**, each with a well-defined responsibility.

### Core Components

- **Ilha**  
  Central controller responsible for island-wide logic and coordination between zones.

- **Zona**  
  Represents a specific zone of the island, containing information about resources, buildings, and workers.

- **Edifício**  
  Stores building-related data such as storage capacity and operational status.

- **Trabalhador**  
  Represents workers, including identification, role, and behavior.

- **GameData**  
  Acts as an intermediary between the user interface and the simulation logic, managing game state and delegating operations.

- **Interface**  
  Handles user interaction, command parsing, and visualization of the island state.

---

## 🧩 Object-Oriented Concepts Applied

- **Encapsulation** – Controlled access to internal state through class interfaces  
- **Inheritance** – Shared behavior across specialized zone and entity types  
- **Polymorphism** – Zone- and worker-specific behavior through method overriding  
- **Separation of Concerns** – Clear distinction between logic, interface, and data  

---

## ⚙️ Simulation Flow

1. Game state is initialized in `main.cpp`
2. User inputs commands through the text-based interface
3. Commands are interpreted and validated by `GameData`
4. Island and zone states are updated accordingly
5. Automatic events execute at day start and end

This loop continues until an end condition is reached.

---

## 🛠 Technology Stack

- **Language:** C++  
- **Paradigm:** Object-Oriented Programming  
- **Interface:** Command-line (text-based)  
- **Architecture:** Modular, class-driven design  

---

## 📂 Source Code

👉 [Island Factory Simulator – GitHub Repository](https://github.com/drouxinol/IslandFactorySimulator)

---

## 🚀 Possible Future Improvements

- Graphical user interface (GUI)
- Save/load system with persistent state
- Expanded building, resource, and worker types
- Improved AI-driven behavior
- Performance optimizations for larger simulations

---

## 🧠 What This Project Demonstrates

- Strong understanding of **C++ and object-oriented design**
- Ability to model **complex systems and interactions**
- Experience managing a **medium-sized codebase**
- Implementation of deterministic, command-driven simulations
- Clean architecture with extensibility in mind
