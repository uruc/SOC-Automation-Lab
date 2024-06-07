# SOC Automation Lab

**[Uruc Tarim](https://github.com/uruc)**

**Acknowledgment:** This project benefited greatly from the insights and tutorials provided by the YouTube channel [DFIR](https://www.youtube.com/@mydfir). Their comprehensive videos were invaluable in understanding and implementing the various components of the SOC Automation Lab.

## 1. Introduction

### 1.1 Overview
The SOC Automation Project aims to create an automated Security Operations Center (SOC) workflow that streamlines event monitoring, alerting, and incident response. By leveraging powerful open-source tools such as Wazuh, Shuffle, and TheHive, this project enhances the efficiency and effectiveness of SOC operations. The project involves setting up a Windows 10 client with Sysmon for detailed event generation, Wazuh for comprehensive event management and alerting, Shuffle for workflow automation, and TheHive for case management and coordinated response actions.

![SOC Automation Diagram](https://github.com/uruc/SOC-Automation-Lab/blob/main/SOC_Automation_Diagram.png)

### 1.2 Purpose and Goals
- **Automate Event Collection and Analysis:** Ensure security events are collected and analyzed in real-time with minimal manual intervention, enabling proactive threat detection and response.
- **Streamline Alerting Process:** Automate the process of generating and forwarding alerts to relevant systems and personnel, reducing response times and minimizing the risk of overlooking critical incidents.
- **Enhance Incident Response Capabilities:** Automate responsive actions to security incidents, improving reaction time, consistency, and effectiveness in mitigating threats.
- **Improve SOC Efficiency:** Reduce the workload on SOC analysts by automating routine tasks, allowing them to focus on high-priority issues and strategic initiatives.

## 2. Prerequisites

### 2.1 Hardware Requirements
- A host machine capable of running multiple virtual machines simultaneously.
- Sufficient CPU, RAM, and disk space to support the VMs and their expected workloads.

### 2.2 Software Requirements
- **VMware Workstation/Fusion:** Industry-standard virtualization platform for creating and managing virtual machines.
- **Windows 10:** The client machine for generating realistic security events and testing the SOC automation workflow.
- **Ubuntu 22.04:** The stable and feature-rich Linux distribution for deploying Wazuh and TheHive.
- **Sysmon:** A powerful Windows system monitoring tool that provides detailed event logging and telemetry.

### 2.3 Tools and Platforms
- **Wazuh:** An open-source, enterprise-grade security monitoring platform that serves as the central point for event collection, analysis, and alerting.
- **Shuffle:** A flexible, open-source security automation platform that handles workflow automation for alert processing and response actions.
- **TheHive:** A scalable, open-source Security Incident Response Platform designed for SOCs to efficiently manage and resolve incidents.
- **VirusTotal:** An online service that analyzes files and URLs to detect various types of malicious content using multiple antivirus engines and scanners.
- **Cloud Services or Additional VMs:** Wazuh and TheHive can be deployed either on cloud infrastructure or additional virtual machines, depending on your resource availability and preferences.

### 2.4 Prior Knowledge
- **Basic Understanding of Virtual Machines:** Familiarity with setting up and managing VMs using VMware or similar virtualization platforms.
- **Basic Linux Command Line Skills:** Ability to perform essential tasks in a Linux environment, such as installing software packages and configuring services.
- **Knowledge of Security Operations and Tools:** Foundational understanding of security monitoring, event logging, and incident response concepts and tools.

## 3. Setup

### 3.1 Step 1: Install and Configure Windows 10 with Sysmon

**3.1.1 Install Windows 10 on VMware:**
 
   ![Windows 10 Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603131110.png)


**3.1.2 Download Sysmon:**

   ![Sysmon Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603131150.png)

**3.1.3 Download Sysmon configuration files from [Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular):**

   ![Sysmon Modular Config](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603131815.png)
   ![Sysmon Modular Config Files](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603132002.png)

**3.1.4 Extract the Sysmon zip file and open PowerShell as an administrator. Navigate to the Sysmon directory extracted from the zip file:**

   ![Extract Sysmon Zip](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603133020.png)

**3.1.5 Place the Sysmon configuration file into the Sysmon directory as well.**

**3.1.6 Before installing Sysmon, check if it is already installed on the Windows machine by verifying:**
 
   - Services
   - Event Viewer > Applications and Services Logs > Microsoft > Windows

   ![Check Sysmon Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603133433.png)

**3.1.7 Since Sysmon is not installed, proceed with the installation using the command:**

```
.\Sysmon64.exe -i .\sysmonconfig.xml
```

   ![Install Sysmon](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603154817.png)

**3.1.8 After a short installation, verify that Sysmon is installed on the system:**

   ![Verify Sysmon Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603154953.png)

With this step, our Windows 10 machine with Sysmon is ready. The next step is setting up Wazuh.

### 3.2 Step 2: Set Up Wazuh Server

**3.2.1 Create a Droplet on DigitalOcean:**
To set up the Wazuh server, we will be using DigitalOcean, a popular cloud service provider. However, you can use any other cloud platform or virtual machines as well. We start by creating a new Droplet from the DigitalOcean menu:

![Create Droplet](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603215218.png)

We select Ubuntu 22.04 as our operating system for the Droplet:

![Select Ubuntu](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603220120.png)

We use a root password for authentication and change the Droplet name to "Wazuh", then create the Droplet:

![Create Wazuh Droplet](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603220521.png)

**3.2.2 Set Up a Firewall:**
Next, we need to set up a firewall to prevent unauthorized access and external scan spams. From the DigitalOcean menu, go to Networking > Firewall > Create Firewall:

![Create Firewall](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603220742.png)

We modify the inbound rules to allow access only from our own IP address:

![Set Inbound Rules](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603220920.png)

After setting up the firewall rules, we apply the firewall to our Wazuh Droplet:

![Apply Firewall](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603221926.png)
![Firewall Protection](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603222113.png)

Now our firewall is protecting the Wazuh virtual machine.

**3.2.3 Connect to the Wazuh Server via SSH:**
From the DigitalOcean left-side menu, go to Droplets > Wazuh > Access > Launch Droplet Console. This allows us to connect to the Wazuh server using SSH:

![Launch Droplet Console](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603223020.png)

**3.2.4 Update and Upgrade the System:**
First, we update and upgrade the system to ensure we have the latest packages and security patches:
```
sudo apt-get update && sudo apt-get upgrade
```
**3.2.5 Install Wazuh:**
We start the Wazuh installation using the official Wazuh installer script:
```
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
The installation process will begin:

![Wazuh Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603224933.png)

We take note of the generated password for the "admin" user:
```
User: admin
Password: *******************
```

**3.2.6 Access the Wazuh Web Interface:**
To log in to the Wazuh web interface, we open a web browser and enter the Wazuh server's public IP address with `https://` prefix:

![Wazuh Login](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603225355.png)

Click "Proceed" and "Continue" to bypass the self-signed SSL certificate warning:

![Wazuh Login Continue](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603225424.png)

Use the generated password with the username "admin" to log in to the Wazuh web interface:

![Wazuh Dashboard](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603225621.png)

Now we have our client machine and Wazuh server up and running. The next step is to install TheHive.

### 3.3 Step 3: Install TheHive

**3.3.1 Create a New Droplet for TheHive:**
We create another Droplet on DigitalOcean with Ubuntu 22.04 for hosting TheHive:

![Create TheHive Droplet](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603230036.png)

Also, enable the firewall that we set up earlier for the TheHive Droplet.

**3.3.2 Install Dependencies:**
We start by installing the necessary dependencies for TheHive:
```
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```

![Install Dependencies](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603230509.png)

**3.3.3 Install Java:**
```
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

**3.3.4 Install Cassandra:**
Cassandra is the database used by TheHive for storing data.
```
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

**3.3.5 Install Elasticsearch:**
Elasticsearch is used by TheHive for indexing and searching data.
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

**3.3.6 Optional Elasticsearch Configuration:**
Create a `jvm.options` file under `/etc/elasticsearch/jvm.options.d` and add the following configurations to optimize Elasticsearch performance:
```
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```

**3.3.7 Install TheHive:**
```
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

Default credentials for accessing TheHive on port 9000:
```
Username: admin@thehive.local
Password: secret
```

![TheHive Login](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603231319.png)

### 3.4 Step 4: Configure TheHive and Wazuh

**3.4.1 Configure Cassandra:**
Cassandra is TheHive's database. We need to configure it by modifying the `cassandra.yaml` file:
```
nano /etc/cassandra/cassandra.yaml
```
This is where we customize the listen address, ports, and cluster name.

![Cassandra Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603231723.png)

Set the `listen_address` to TheHive's public IP:

![Listen Address](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603232121.png)

Next, configure the RPC address by entering TheHive's public IP.

Lastly, change the seed address under the `seed_provider` section. Enter TheHive's public IP in the `seeds` field:

![Seed Provider](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603232508.png)

Stop the Cassandra service:
```
systemctl stop cassandra.service
```
Remove the old Cassandra data files since we installed TheHive using the package:
```
rm -rf /var/lib/cassandra/*
```
Start the Cassandra service again:
```
systemctl start cassandra.service
```
Check the Cassandra service status to ensure it's running:
```
systemctl status cassandra.service
```

![Cassandra Service Status](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603232813.png)

**3.4.2 Configure Elasticsearch:**
Elasticsearch is used for data indexing in TheHive. We need to configure it by modifying the `elasticsearch.yml` file:
```
nano /etc/elasticsearch/elasticsearch.yml
```

Optionally, change the cluster name.
Uncomment the `node.name` field.
Uncomment the `network.host` field and set the IP to TheHive's public IP.

![Elasticsearch Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603233522.png)

Optionally, uncomment the `http.port` field (default port is 9200).
Optionally, uncomment the `cluster.initial_master_nodes` field, remove `node-2` if not applicable.

Start and enable the Elasticsearch service:
```
systemctl start elasticsearch
systemctl enable elasticsearch
```

Check the Elasticsearch service status:
```
systemctl status elasticsearch
```

![Elasticsearch Service Status](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603233935.png)

**3.4.3 Configure TheHive:**
Before configuring TheHive, ensure the `thehive` user and group have access to the necessary file paths:
```
ls -la /opt/thp
```

![TheHive Directory Permissions](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603234256.png)

If `root` has access to the `thehive` directory, change the ownership:
```
chown -R thehive:thehive /opt/thp
```
This command changes the owner to the `thehive` user and group for the specified directories.

![Change TheHive Directory Permissions](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603234450.png)

Now, configure TheHive's configuration file:
```
nano /etc/thehive/application.conf
```

Modify the `database` and `index config` sections.
Change the `hostname` IP to TheHive's public IP.
Set the `cluster.name` to the same value as the Cassandra cluster name ("Test Cluster" in this example).
Change the `index.search.hostname` to TheHive's public IP.
At the bottom, change the `application.baseUrl` to TheHive's public IP.

By default, TheHive has both Cortex (data enrichment and response) and MISP (threat intelligence platform) enabled.

![TheHive Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603235441.png)

Save the file, start, and enable the TheHive service:
```
systemctl start thehive
systemctl enable thehive
```

![TheHive Service Status](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603235616.png)

Important note: If you cannot access TheHive, ensure all three services (Cassandra, Elasticsearch, and TheHive) are running. If any of them are not running, TheHive won't start.

If all services are running, access TheHive from a web browser using TheHive's public IP and port 9000:
```
http://143.198.56.201:9000/login
```

![TheHive Login](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603235840.png)

Log in to TheHive using the default credentials:
Username: `admin@thehive.local`
Password: `secret`

![TheHive Dashboard](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604000101.png)

### 3.5 Step 5: Configure Wazuh

**3.5.1 Add a Windows Agent in Wazuh:**
Log in to the Wazuh web interface.
Click on "Add agent" and select "Windows" as the agent's operating system.
Set the server address to the Wazuh server's public IP.

![Add Wazuh Agent](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604000526.png)

Copy the installation command provided and execute it in PowerShell on the Windows client machine. The Wazuh agent installation will start.

![Wazuh Agent Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002346.png)

After the installation, start the Wazuh agent service using the `net start wazuhsvc` command or through Windows Services.

![Wazuh Agent Service](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002550.png)
![Wazuh Agent Service Start](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002624.png)

**3.5.2 Verify the Wazuh Agent:**
Check the Wazuh web interface to confirm the Windows agent is successfully connected.

![Wazuh Agent Connected](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002744.png)

The Windows agent should be listed with an "Active" status.

![Wazuh Agent Status](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002929.png)

Now you can start querying events from the Windows agent in Wazuh.

## 4. Generating Telemetry and Custom Alerts

### 4.1 Configure Sysmon Event Forwarding to Wazuh

**4.1.1 Modify Wazuh Agent Configuration:**
On the Windows client machine, navigate to `C:\Program Files (x86)\ossec-agent` and open the `ossec.conf` file with a text editor (e.g., Notepad).

![Ossec Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604144648.png)

**4.1.2 Add Sysmon Event Forwarding:**
In the `ossec.conf` file, add a new `<localfile>` section to configure Sysmon event forwarding to Wazuh.
Check the full name of the Sysmon event log in the Windows Event Viewer.

![Sysmon Event Log](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604150516.png)

Add the following configuration to the `ossec.conf` file:

![Ossec Sysmon Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604150556.png)

Optional: You can also configure forwarding for other event logs like PowerShell, Application, Security, and System. In this lab, we will remove the Application, Security, and System sections to focus on Sysmon events.

**4.1.3 Save the Configuration File:**
Since modifying the `ossec.conf` file requires administrator privileges, open a new Notepad instance with administrator rights and save the changes to the file.

**4.1.4 Restart the Wazuh Agent Service:**
Restart the Wazuh agent service to apply the configuration changes.

![Restart Wazuh Agent Service](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604151539.png)

Note: Whenever you modify the Wazuh agent configuration, you need to restart the service either through PowerShell or Windows Services.

**4.1.5 Verify Sysmon Event Forwarding:**
In the Wazuh web interface, go to the "Events" section and search for Sysmon events to confirm they are being received.

![Search Sysmon Events](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604152334.png)

### 4.2 Generate Mimikatz Telemetry

**4.2.1 Download Mimikatz:**
On the Windows client machine, download Mimikatz, a tool commonly used by attackers and red teamers to extract credentials from memory.
To download Mimikatz, you may need to temporarily disable Windows Defender or exclude the download directory from scanning.

![Disable Windows Defender](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604152850.png)

**4.2.2 Execute Mimikatz:**
Open PowerShell, navigate to the directory where Mimikatz is downloaded, and execute it.

![Start Mimikatz](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604153518.png)

**4.2.3 Configure Wazuh to Log All Events:**
By default, Wazuh only logs events that trigger a rule or alert. To log all events, modify the Wazuh manager's `ossec.conf` file.
Connect to the Wazuh server via SSH and open `/var/ossec/etc/ossec.conf`.
Create a backup of the original configuration file:
```
cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf
```

![Wazuh Ossec Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604154130.png)

Change the `<logall>` and `<logall_json>` options under the `<ossec_config>` section from "no" to "yes".
Restart the Wazuh manager service:
```
systemctl restart wazuh-manager.service
```

This configuration forces Wazuh to archive all logs in the `/var/ossec/logs/archives/` directory.

**4.2.4 Configure Filebeat:**
To enable Wazuh to ingest the archived logs, modify the Filebeat configuration:
```
nano /etc/filebeat/filebeat.yml
```

![Filebeat Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604154620.png)

Change the `enabled: false` to `true` for the "archives" input and restart the Filebeat service.

**4.2.5 Create a New Index in Wazuh:**
After updating Filebeat and the Ossec configuration, create a new index in the Wazuh web interface to search the archived logs.
From the left-side menu, go to "Stack Management" > "Index Management".

![Create Wazuh Index](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604154910.png)

Create a new index named `wazuh-archives-*` to cover all archived logs.

![Wazuh Archives Index](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604155026.png)

On the next page, select "timestamp" as the time field and create the index.

![Create Wazuh Archives Index](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604155124.png)

Go to the "Discover" section from the left-side menu and select the newly created index.

![Discover Wazuh Archives](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604155204.png)

**4.2.6 Troubleshoot Mimikatz Logs:**
To troubleshoot if Mimikatz logs are being archived, use `cat` and `grep` on the archive logs in the Wazuh manager CLI:
```
cat /var/ossec/logs/archives/archives.log | grep -i mimikatz
```

![Check Mimikatz Logs](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604155940.png)

If no Mimikatz events are found in the archives, it means no Mimikatz event was generated, and you won't see any related events in the Wazuh web interface.

**4.2.7 Relaunch Mimikatz:**
Relaunch Mimikatz on the Windows client machine and check the Event Viewer to ensure Sysmon is capturing Mimikatz events.

![Mimikatz Sysmon Event](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604160828.png)

Check the archive file again for Mimikatz logs to confirm they are being generated.

![Mimikatz Logs Generated](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604164746.png)
![Mimikatz Logs](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604164803.png)

### 4.3 Create a Custom Mimikatz Alert

**4.3.1 Analyze Mimikatz Logs:**
Examine the Mimikatz logs and identify a suitable field for crafting an alert. In this example, we will use the `originalfilename` field.

![Mimikatz Original Filename](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604165046.png)

Using the `originalfilename` field ensures the alert will trigger even if an attacker changes the Mimikatz executable name.

**4.3.2 Create a Custom Rule:**
You can create a custom rule either from the CLI or the Wazuh web interface.

![Wazuh Rules](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604165457.png)

In the web interface, click on the "Manage rule files" button. Filter the rules by name (e.g., "sysmon") and view the rule details by clicking the eye icon.

![Sysmon Rules](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604165717.png)

These are Sysmon-specific rules built into Wazuh for event ID 1. Copy one of these rules as a reference and modify it to create a custom Mimikatz detection rule.

Example custom rule:
```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)\\mimikatz\.exe</field>
  <description>Mimikatz Usage Detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

Go to the "Custom rules" button and edit the "local_rules.xml" file. Add the custom Mimikatz detection rule.

![Custom Mimikatz Rule](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604171432

png)
![Custom Mimikatz Rule Added](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604171857.png)

Save the file and restart the Wazuh manager service.

**4.3.3 Test the Custom Rule:**
To test the custom rule, rename the Mimikatz executable on the Windows client machine to something different.

![Renamed Mimikatz](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604172430.png)

Execute the renamed Mimikatz.

![Mimikatz Started](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604172710.png)

Verify that the custom rule triggers an alert in Wazuh, even with the renamed Mimikatz executable.

![Mimikatz Alert Triggered](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604173838.png)

## 5. Automation with Shuffle and TheHive

### 5.1 Set Up Shuffle

**5.1.1 Create a Shuffle Account:**
Go to the Shuffle website (shuffler.io) and create an account.

![Shuffle Account](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604213121.png)

**5.1.2 Create a New Workflow:**
Click on "New Workflow" and create a workflow. You can select any random use case for demonstration purposes.

![Create Shuffle Workflow](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604213428.png)

**5.1.3 Add a Webhook Trigger:**
On the workflow page, click on "Triggers" at the bottom left. Drag a "Webhook" trigger and connect it to the "Change Me" node.
Set a name for the webhook and copy the Webhook URI from the right side. This URI will be added to the Ossec configuration on the Wazuh manager.

![Shuffle Webhook](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604213723.png)

**5.1.4 Configure the "Change Me" Node:**
Click on the "Change Me" node and set it to "Repeat back to me" mode. For call options, select "Execution argument". Save the workflow.

![Shuffle Workflow Settings](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/2024-06-04%2021_41_05-Workflow%20-%20SOC%20Automation%20Lab.png)

**5.1.5 Configure Wazuh to Connect to Shuffle:**
On the Wazuh manager CLI, modify the `ossec.conf` file to add an integration for Shuffle:
```
nano /var/ossec/etc/ossec.conf
```

Add the following integration configuration:
```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_0af8a049-f2cb-420b-af58-5ebc3c40c7df</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

Replace the `<level>` tag with `<rule_id>100002</rule_id>` to send alerts based on the custom Mimikatz rule ID.

![Wazuh Shuffle Integration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604225725.png)

Restart the Wazuh manager service:
```
systemctl restart wazuh-manager.service
```

**5.1.6 Test the Shuffle Integration:**
Regenerate the Mimikatz telemetry on the Windows client machine.
In Shuffle, click on the webhook trigger ("Wazuh-Alerts") and click "Start".

![Shuffle Webhook Start](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604230243.png)

Verify that the alert is received in Shuffle.

### 5.2 Build a Mimikatz Workflow

**Workflow Steps:**
1. Mimikatz alert sent to Shuffle
2. Shuffle receives Mimikatz alert / extract SHA256 hash from file
3. Check reputation score with VirusTotal
4. Send details to TheHive to create an alert
5. Send an email to the SOC analyst to begin the investigation

**5.2.1 Extract SHA256 Hash:**
Observe that the return values for the hashes are appended by their hash type (e.g., `sha1=hashvalue`).
To automate the workflow, parse out the hash value itself. Sending the entire value, including `sha1=`, to VirusTotal will result in an invalid query.

Click on the "Change Me" node and select "Regex capture group" instead of "Repeat back to me".
In the "Input data", select the "hashes" option.
In the "Regex" tab, enter the regex pattern to parse the SHA256 hash value: `SHA256=([0-9A-Fa-f]{64})`.
Save the workflow.

![Shuffle Regex](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604234504.png)

Click on the "Show execution" button (running man icon) to verify that the hash value is extracted correctly.

![Extracted Hash Value](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604234729.png)

**5.2.2 Integrate VirusTotal:**
Create a VirusTotal account to access the API.

![VirusTotal Account](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604235908.png)

Copy the API key and return to Shuffle.
In Shuffle, click on the "Apps" tab and search for "VirusTotal". Drag the "VirusTotal" app to the workflow, and it will automatically connect.

![VirusTotal App](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605000230.png)

Enter the API key on the right side or click "Authenticate VirusTotal v3" to authenticate.

![VirusTotal Authentication](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605000358.png)

Change the "ID" field to the "SHA256Regex" value created earlier.

![VirusTotal ID](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605001826.png)

Save the workflow and rerun it.

![VirusTotal Results](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605001925.png)

Expand the results to view the VirusTotal scan details, including the number of detections.

![VirusTotal Detection](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605002209.png)

**5.2.3 Integrate TheHive:**
In Shuffle, search for "TheHive" in the "Apps" and drag it into the workflow.
TheHive can be connected using the IP address and port number (9000) of the TheHive instance created on DigitalOcean.

![TheHive Login](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605112834.png)

Log in to TheHive using the default credentials:
Username: `admin@thehive.local`
Password: `secret`

**5.2.4 Configure TheHive:**
Create a new organization and user for the organization in TheHive.

![TheHive Organizations](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605113123.png)

Add new users with different profiles as needed.

![TheHive Users](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605113317.png)

Set new passwords for the users.
For the SOAR user created for Shuffle integration, generate an API key.

![TheHive API Key](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605113655.png)

Create an API key and store it securely. This key will be used to authenticate Shuffle.
Log out from the admin account and log in with one of the user accounts.

![TheHive Dashboard](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605115228.png)

**5.2.5 Configure Shuffle to Work with TheHive:**
In Shuffle, click on the orange "Authenticate TheHive" button and enter the API key created earlier.
For the URL, enter the public IP address of TheHive along with the port number.

![Shuffle TheHive Authentication](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605115759.png)

Under "Find actions", click on "TheHive" and select "Create alerts".
Set the JSON payload for TheHive to receive the alerts. Here's an example payload for the Mimikatz scenario:

```json
{
  "description": "Mimikatz Detected on host: DESKTOP-HS8N3J7",
  "externallink": "",
  "flag": false,
  "pap": 2,
  "severity": "2",
  "source": "Wazuh",
  "sourceRef": "Rule:100002",
  "status": "New",
  "summary": "Details about the Mimikatz detection",
  "tags": [
    "T1003"
  ],
  "title": "Mimikatz Detection Alert",
  "tlp": 2,
  "type": "Internal"
}
```

Expand the "Body" section to set the payload.

![Shuffle TheHive Body](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605141313.png)

Set the payload on the left side and test the output on the right side.

![Shuffle TheHive Payload](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605145351.png)

Save the workflow and rerun it. An alert should appear in the TheHive dashboard.

![TheHive Alert](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605143428.png)

Note: If the alert doesn't appear, ensure that the firewall for TheHive in your cloud provider allows inbound traffic on port 9000 from any source.

Click on the alert to view the details.

![TheHive Alert Details](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605145839.png)

To include more information in the alert, customize the fields in TheHive's JSON payload.
For example, let's create a more detailed summary.
In Shuffle, click on the "Show Body" button to view the available JSON payload fields.

In the summary field, you can include additional details like the technique and command line associated with the alert.

![Shuffle TheHive Summary](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605165035.png)

Refer to the body part of TheHive in Shuffle to determine what to include in these fields.

![Shuffle TheHive Body](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605165143.png)

Save and rerun the workflow to see the updated alert with more information.

![TheHive Alert Updated](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605164956.png)

**5.2.6 Send Email Notification:**
In Shuffle, find "Email" in the "Apps" and connect VirusTotal to the email node.

![Shuffle Email](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605165431.png)

Configure the email settings, including the recipient, subject, and body, to send the alert with relevant event information.

![Shuffle Email Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605170704.png)

Save the workflow and rerun it.

![Shuffle Workflow Final](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605170809.png)

Verify that the email is received with the expected alert details.

![Email Received](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605170915.png)

## 6. Conclusion

We have successfully set up and configured the SOC Automation Lab, integrating Wazuh, TheHive, and Shuffle for automated event monitoring, alerting, and incident response. This foundation provides a solid starting point for further customization and expansion of automation workflows to meet our specific SOC requirements.
The key steps and achievements of this lab include:

1. Installing and configuring a Windows 10 client with Sysmon for detailed event generation.
2. Setting up Wazuh as the central event management and alerting platform.
3. Installing and configuring TheHive for case management and coordinated response actions.
4. Generating Mimikatz telemetry and creating custom alerts in Wazuh.
5. Integrating Shuffle as the SOAR platform for workflow automation.
6. Building an automated workflow to extract file hashes, check reputation scores with VirusTotal, create alerts in TheHive, and notify SOC analysts via email.

With this lab, we have gained hands-on experience in implementing an automated SOC workflow using powerful open-source tools. We can now leverage this knowledge to enhance your organization's security operations, improve incident response times, and streamline SOC processes.

Remember to continuously refine and adapt your automation workflows based on evolving threats, new tools, and changing business requirements. Regularly review and update your SOC playbooks, integrate additional threat intelligence sources, and explore advanced features of the tools used in this lab.

By embracing automation and leveraging the capabilities of Wazuh, TheHive, and Shuffle, you can build a more efficient, effective, and resilient SOC that proactively detects and responds to security incidents.

## 7. References
- https://www.mydfir.com/
- https://www.youtube.com/watch?v=Lb_ukgtYK_U
