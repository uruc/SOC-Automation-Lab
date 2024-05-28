# SOC Automation Project

**Author: [Ibrahim Uruc Tarim](https://github.com/uruc)**

## Introduction

### Overview
The SOC Automation Project aims to create an automated Security Operations Center (SOC) workflow that streamlines event monitoring, alerting, and incident response. By leveraging tools such as Wazuh, Shuffle, and TheHive, this project will enhance the efficiency and effectiveness of SOC operations. The project involves setting up a Windows 10 client with Sysmon for event generation, Wazuh for event management and alerting, Shuffle for automation, and TheHive for case management and response actions.

![SOC Automation Diagram](https://github.com/uruc/SOC-Automation-Project/blob/main/SOC_Automation_Diagram.png)

### Purpose and Goals
- **Automate Event Collection and Analysis:** Ensure security events are collected and analyzed in real-time with minimal manual intervention.
- **Streamline Alerting Process:** Automate the process of generating and forwarding alerts to relevant systems and personnel.
- **Enhance Incident Response Capabilities:** Automate responsive actions to security incidents, improving reaction time and effectiveness.
- **Improve SOC Efficiency:** Reduce the workload on SOC analysts by automating routine tasks, allowing them to focus on critical issues.

## Prerequisites

### Hardware Requirements
- A host machine capable of running multiple virtual machines.
- Sufficient CPU, RAM, and disk space to support the VMs and their operations.

### Software Requirements
- **VMware Workstation/Fusion:** For creating and managing virtual machines.
- **Windows 10:** As the client machine for generating security events.
- **Ubuntu 22.04:** For deploying Wazuh and TheHive.
- **Sysmon:** Installed on Windows 10 for detailed event logging.

### Tools and Platforms
- **Wazuh:** An open-source security monitoring platform that will serve as the central point for event collection, analysis, and alerting.
- **Shuffle:** A security automation platform that will handle the workflow automation for alert processing and response actions.
- **TheHive:** A scalable, open-source Security Incident Response Platform designed for SOCs to efficiently manage and resolve incidents.
- **Cloud Services or Additional VMs:** Wazuh and TheHive can be deployed either on cloud infrastructure or additional virtual machines depending on your resources and preferences.

### Prior Knowledge
- **Basic Understanding of Virtual Machines:** Familiarity with setting up and managing VMs using VMware.
- **Basic Linux Command Line Skills:** Ability to perform basic tasks in a Linux environment, such as installing software and configuring services.
- **Knowledge of Security Operations and Tools:** Understanding of security monitoring, event logging, and incident response concepts.

## Setup

### Step 1: Send Events from Windows 10 Client Wazuh Agent
- Description of the process.
- Configuration details.
- Screenshots of the setup.

## Detailed Steps

### Step 2: Receive Events at Wazuh Manager
- Description of how events are received.
- Configuration details.
- Screenshots.

### Step 3: Send Alerts from Wazuh Manager to Shuffle
- Description of alert sending.
- Configuration details.
- Screenshots.

### Step 4: Enrich IOCs Using OSINT
- Description of enrichment process.
- Configuration details.
- Screenshots.

### Step 5: Send Alerts from Shuffle to TheHive
- Description of the alert forwarding process.
- Configuration details.
- Screenshots.

### Step 6: Send Email Notifications
- Description of email notifications.
- Configuration details.
- Screenshots.

### Step 7: SOC Analyst Interactions with TheHive
- Description of how SOC analysts interact with alerts.
- Screenshots.

### Step 8: Perform Response Actions
- Description of response actions.
- Configuration details.
- Screenshots.

## Conclusion
- Summary of the project.
- Potential improvements or future work.

## References
- Any references or additional reading materials.
