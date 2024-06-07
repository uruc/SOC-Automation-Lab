Here is the updated and completed README file for your SOC Automation Project, with the additional content you provided and the corrected image links:

# SOC Automation Lab

**Author: [Uruc Tarim](https://github.com/uruc)**

## Introduction

### Overview
The SOC Automation Project aims to create an automated Security Operations Center (SOC) workflow that streamlines event monitoring, alerting, and incident response. By leveraging tools such as Wazuh, Shuffle, and TheHive, this project will enhance the efficiency and effectiveness of SOC operations. The project involves setting up a Windows 10 client with Sysmon for event generation, Wazuh for event management and alerting, Shuffle for automation, and TheHive for case management and response actions.

![SOC Automation Diagram](https://github.com/uruc/SOC-Automation-Lab/blob/main/SOC_Automation_Diagram.png)

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
- **VirusTotal:** An online service that analyzes files and URLs to detect viruses, worms, trojans, and other kinds of malicious content.
- **Cloud Services or Additional VMs:** Wazuh and TheHive can be deployed either on cloud infrastructure or additional virtual machines depending on your resources and preferences.

### Prior Knowledge
- **Basic Understanding of Virtual Machines:** Familiarity with setting up and managing VMs using VMware.
- **Basic Linux Command Line Skills:** Ability to perform basic tasks in a Linux environment, such as installing software and configuring services.
- **Knowledge of Security Operations and Tools:** Understanding of security monitoring, event logging, and incident response concepts.

## Setup

### Step 1: Install and Configure Windows 10 with Sysmon

**Install Windows 10 on VMware:**
 
   ![Windows 10 Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603131110.png)


**Download Sysmon:**

   ![Sysmon Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603131150.png)

**Download Sysmon configuration files from [Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular):**

   ![Sysmon Modular Config](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603131815.png)
   ![Sysmon Modular Config Files](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603132002.png)

**Extract the Sysmon zip file and open PowerShell as an administrator. Navigate to the Sysmon directory extracted from the zip file:**

   ![Extract Sysmon Zip](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603133020.png)

**Place the Sysmon configuration file into the Sysmon directory as well.**

**Before installing Sysmon, check if it is already installed on the Windows machine by verifying:**
 
   - Services
   - Event Viewer > Applications and Services Logs > Microsoft > Windows

   ![Check Sysmon Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603133433.png)

**Since Sysmon is not installed, proceed with the installation using the command:**

```
.\Sysmon64.exe -i .\sysmonconfig.xml
```

   ![Install Sysmon](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603154817.png)

**After a short installation, verify that Sysmon is installed on the system:**

   ![Verify Sysmon Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603154953.png)

With this step, our Windows 10 machine with Sysmon is ready. The next step is setting up Wazuh.

### Step 2: Set Up Wazuh Server

To set up the Wazuh server, we will be using DigitalOcean cloud service. However, you can use any other cloud platform or virtual machines as well. We start by creating a droplet from the menu:

![Create Droplet](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603215218.png)

We select Ubuntu 22.04 as our operating system:

![Select Ubuntu](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603220120.png)

We use a root password and change the name to Wazuh, then create the droplet:

![Create Wazuh Droplet](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603220521.png)

Next, we need to set up a firewall to prevent external scan spams:
From Networking > Firewall > Create Firewall:

![Create Firewall](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603220742.png)

We change the inbound rules to only allow our own IP:

![Set Inbound Rules](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603220920.png)

After setting up the firewall, we apply it to our Wazuh server:

![Apply Firewall](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603221926.png)
![Firewall Protection](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603222113.png)

Now our firewall is protecting our virtual machine.

From the left side menu, we go to Droplets > Wazuh > Access > Launch Droplet Console. This allows us to connect to the server via SSH:

![Launch Droplet Console](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603223020.png)

First, we update and upgrade the system:
```
sudo apt-get update && sudo apt-get upgrade
```
Next, we start with the Wazuh installer:
```
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
The installation will start:

![Wazuh Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603224933.png)

We take down the password that is generated:
```
User: admin
Password: *******************
```

To log in to Wazuh, we go to our Wazuh server's public IP in a browser with `https://` in front:

![Wazuh Login](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603225355.png)

Here, click "Proceed" and "Continue":

![Wazuh Login Continue](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603225424.png)

Use the password that was generated with the username "admin", and we are in:

![Wazuh Dashboard](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603225621.png)

Now we have our client machine and Wazuh up and running. The next step is to install TheHive.

For this, we will create another droplet in DigitalOcean with Ubuntu 22.04:

![Create TheHive Droplet](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603230036.png)

Also, enable the firewall that we set up for TheHive.

Now we are going to install some dependencies:
```
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```

![Install Dependencies](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603230509.png)

Next, we start installing Java, Cassandra, Elasticsearch, and TheHive itself.

**Install Java:**
```
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

**Install Cassandra:**
```
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

**Install Elasticsearch:**
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

**Optional Elasticsearch Configuration:**
Create a `jvm.options` file under `/etc/elasticsearch/jvm.options.d` and put the following configurations in that file:
```
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```

**Install TheHive:**
```
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

Default Credentials on port 9000:
```
credentials are 'admin@thehive.local' with a password of 'secret'
```

![TheHive Login](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603231319.png)

After finishing all the installations, the next step is to configure everything.
First, we will configure TheHive and the Wazuh server, and our Windows 10 client will be reporting to Wazuh.

First, we will start with TheHive's Cassandra, which is TheHive's database.
```
nano /etc/cassandra/cassandra.yaml
```
This is where we customize our listen address or ports, along with the cluster names.

![Cassandra Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603231723.png)

Here, we want to set the `listen_address` to our TheHive's public IP:

![Listen Address](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603232121.png)

Next is the RPC address. We do the same, entering our TheHive's public IP address.
Lastly, we will be changing the seed address. Look for the `seed_provider`.
We do the same and enter the public IP of TheHive in the `seeds`:

![Seed Provider](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603232508.png)

The next step is to stop our Cassandra service:
```
systemctl stop cassandra.service
```
And because we installed TheHive using the package, we must remove the old files:
```
rm -rf /var/lib/cassandra/*
```
Now we can start the service again:
```
systemctl start cassandra.service
```
We check the service just in case with:
```
systemctl status cassandra.service
```

![Cassandra Service Status](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603232813.png)

The next step is to set up Elasticsearch, which will be used for data indexing.
```
nano /etc/elasticsearch/elasticsearch.yml
```

Here, we can change the name of the cluster (optional).
We need to uncomment the `node.name`.
And third, we need to uncomment the `network.host` and change the IP to our TheHive's public IP.

![Elasticsearch Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603233522.png)

Additionally, we can uncomment the `http.port` as optional because the default port is 9200.
And we can also optionally uncomment the `cluster.initial_master_nodes: ["node-1", "node-2"]` and remove `node-2` since we don't have it.

Now we can start the Elasticsearch service and then enable it:
```
systemctl start elasticsearch
systemctl enable elasticsearch
```

And checking the service:
```
systemctl status elasticsearch
```

![Elasticsearch Service Status](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603233935.png)

The next step is to start configuring TheHive.
Before we configure TheHive's configuration file, we want to make sure that the `thehive` user and group have access to a certain file path.
```
ls -la /opt/thp
```

![TheHive Directory Permissions](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603234256.png)

We see there that `root` has access to the `thehive` directory, so we need to change that:
```
chown -R thehive:thehive /opt/thp
```
This essentially means to change the owner to the `thehive` user and group for the destination directories.

![Change TheHive Directory Permissions](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603234450.png)

Now we can configure TheHive's configuration file:
```
nano /etc/thehive/application.conf
```

We go to the line `database` and `index config`.
First, we change the `hostname` IP to our TheHive's public IP.
Second, we change the `cluster.name` to the same as the Cassandra cluster name, which was "Test Cluster".
Then, we change the `index.search.hostname` to our public IP as well.
And at the bottom, we change the `application.baseUrl` to our public IP as well.

By default, TheHive has both Cortex and MISP enabled.
Cortex is their data enrichment and response capability, whereas MISP is used as their CTI platform.

![TheHive Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603235441.png)

We save this file and start and enable the service:
```
systemctl start thehive
systemctl enable thehive
```

![TheHive Service Status](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603235616.png)

Important note: If you cannot access TheHive, make sure to check all 3 services: Cassandra, Elasticsearch, and TheHive. All of them should be running; otherwise, TheHive won't start.

If all services are running, we can connect to TheHive from the browser using the public IP of TheHive and port 9000:
```
http://143.198.56.201:9000/login
```

![TheHive Login](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240603235840.png)

We can log in to TheHive using the default login, which is `admin@thehive.local`, and the password is `secret`.

![TheHive Dashboard](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604000101.png)

Now that we have TheHive configured, we move on to Wazuh for configuration.
We log in to the Wazuh dashboard.

Now we will add an agent to Wazuh.
Click on "Add agent", select "Windows" since we have a Windows client.
The next server address is our Wazuh public IP.

![Add Wazuh Agent](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604000526.png)

Now we copy the command at the bottom and go to our Windows machine.
Open PowerShell and paste it, and the installation will start.

![Wazuh Agent Installation](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002346.png)

After this, we start the service with the `net start wazuhsvc` command.
We can also start it or control it from the Services.

![Wazuh Agent Service](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002550.png)
![Wazuh Agent Service Start](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002624.png)

Now we can go and check from the Wazuh dashboard to see the agent.

![Wazuh Agent Connected](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002744.png)

We see that our Windows agent is successfully checking into Wazuh.

![Wazuh Agent Status](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604002929.png)

Now we can start querying events from our agent.

Next, we will generate telemetry from our Windows 10 machine and make sure it is being digested by Wazuh.
We will send telemetry containing Mimikatz and trigger a custom alert.

We go to `C:\Program Files (x86)\ossec-agent` in the Windows machine and open the `ossec.conf` file with Notepad.

![Ossec Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604144648.png)

Now we will add a `<localfile>` section in this config to ingest Sysmon.
First, we check the full name of Sysmon from the Event Viewer.

![Sysmon Event Log](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604150516.png)

We change the name here:

![Ossec Sysmon Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604150556.png)

We could do the same if we wanted to ingest PowerShell.
For the sake of this lab, we will remove the Application, Security, and System sections. This means that Application, Security, and System events will no longer be forwarded to our Wazuh manager.
You can leave them on if you like.

Because customizing the `ossec.conf` file needs administrator permissions, open a new Notepad instance with administrator power, and then open the `ossec.conf` file into this Notepad and save.

Next, we restart the Wazuh service:

![Restart Wazuh Agent Service](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604151539.png)

Anytime you change the Wazuh configuration, you need to restart the service from either PowerShell or Windows Services.

Next, we head over to the Wazuh dashboard, and under "Events", we can start searching for Sysmon events.

![Search Sysmon Events](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604152334.png)

The next step is to download Mimikatz on the Windows machine.
To be able to download Mimikatz onto our Windows machine, we need to either disable Windows Defender or exclude the directory where we will download it.
Mimikatz is an application that attackers or red teamers use to extract credentials from the target machine.

![Disable Windows Defender](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604152850.png)

Then we download Mimikatz, open PowerShell, go to the location of Mimikatz, and start it.

![Start Mimikatz](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604153518.png)

Wazuh, by default, does not log everything and only logs things when a rule or alert is triggered.
We can change this by going to the Wazuh manager, configuring the `ossec.conf` file, and making it log everything or create a rule that looks at specific events.

Now let's go and modify the `ossec.conf` and log everything for Wazuh.
We connect to the Wazuh server with SSH and go to `/var/ossec/etc/ossec.conf`.
First, we copy the original configuration file just in case:
```
cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf
```
Then we can go and change the configuration file.

![Wazuh Ossec Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604154130.png)

First, we change the `<logall>` and `<logall_json>` options under the `<ossec_config>` section from "no" to "yes".
Now let's restart the Wazuh manager:
```
systemctl restart wazuh-manager.service
```

What this does is force Wazuh to begin archiving all the logs and put them into the directory called "archives". This file is located in `/var/ossec/logs/archives/`.
In order for Wazuh to start ingesting these logs, we need to change the configuration in Filebeat.

We go to:
```
nano /etc/filebeat/filebeat.yml
```

![Filebeat Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604154620.png)

Here, we change the `enabled: false` to `true` for the "archives" input and restart the Filebeat service.

Now that we've updated Filebeat and the Ossec configuration, let's head back to the Wazuh dashboard and create a new index.

From the Wazuh left-side menu, go to "Stack Management" > "Index Management".

![Create Wazuh Index](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604154910.png)

Create a new index for archives so we can search all the logs.
We put the name `wazuh-archives-*` for everything.

![Wazuh Archives Index](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604155026.png)

On the next page, we select "timestamp" as the time field and create our index.

![Create Wazuh Archives Index](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604155124.png)

Next, we go to the left-side menu > "Discover" and select our new index.

![Discover Wazuh Archives](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604155204.png)

Wazuh, by default, does not include all logs in the manager. Only those that trigger the rules will show up. That's why we had to configure the logs to log everything, making it so that regardless of a rule being triggered or not, we want the manager to archive it to allow us to search for them.

So, in our Wazuh manager CLI, to troubleshoot if Mimikatz logs are being archived, we use `cat` and `grep` on the archive logs:
```
cat /var/ossec/logs/archives/archives.log | grep -i mimikatz
```

![Check Mimikatz Logs](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604155940.png)

If we don't see anything in the archives, then a Mimikatz event did not generate. This means no matter what, we won't see any Mimikatz events in our dashboard.

So, we will relaunch Mimikatz from the Windows 10 machine. We also check the Event Viewer to make sure Sysmon is capturing Mimikatz.

![Mimikatz Sysmon Event](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604160828.png)

Check our archive file again for Mimikatz and see that logs are generated.

![Mimikatz Logs Generated](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604164746.png)
![Mimikatz Logs](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604164803.png)

Looking at these logs and checking the fields, we will use the `originalfilename` field to craft our alert.

![Mimikatz Original Filename](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604165046.png)

Because if we were to use a field such as `image`, an attacker would simply change the name of Mimikatz, and the alert would be bypassed. But by building an alert on the `originalfilename` field, we can neglect this.

Now we can create a rule from both CLI or the dashboard.

![Wazuh Rules](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604165457.png)

Here, we go to the "Manage rule files" button. Here, we can filter the rules by name, and when we filter for "sysmon", we can look into the rules by clicking the eye icon.

![Sysmon Rules](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604165717.png)

These are Sysmon rules that are built into Wazuh, specifically targeting event ID 1. We will copy one of these as a reference and build it out as a custom rule to detect Mimikatz.

So, we take this rule and change it as we want:
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

And we go to the "Custom rules" button on the previous page. Here, we go to edit this "local_rules.xml" file and add our rule for Mimikatz.

![Custom Mimikatz Rule](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604171432.png)
![Custom Mimikatz Rule Added](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604171857.png)

After we save the file and restart the manager, we can also change the name of the Mimikatz file to something else to test the rules that we created. Because in theory, changing the file name would not work, and our rule should catch Mimikatz regardless.

![Renamed Mimikatz](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604172430.png)

And we start Mimikatz.

![Mimikatz Started](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604172710.png)

And here we go:

![Mimikatz Alert Triggered](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604173838.png)

We even used our renamed Mimikatz, and the alert still triggered.

For the next step, we will begin performing some automation using Shuffle and TheHive.

Shuffle is our SOAR platform, and we connect it to TheHive to send the alert and then send it to our SOC analyst. After this step, we will have a fully functional lab that integrates Wazuh, TheHive, and Shuffle.

Wazuh itself is a strong system, but we will also see how we can utilize SOAR and case management systems like TheHive.

First, we go to the Shuffle website (shuffler.io) and create an account.

![Shuffle Account](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604213121.png)

Next, we click on "New Workflow" and create our workflow.
You can select any random use cases.

![Create Shuffle Workflow](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604213428.png)

After clicking "Done", we head over to this page, and first, on the bottom left of the page, we select "Triggers".
Here, we take a "Webhook" and connect it to "Change Me". Then, we set its name and copy the Webhook URI on the right side because we will need to add this into our Ossec configuration hosted on the Wazuh manager.

![Shuffle Webhook](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604213723.png)

Before going to Wazuh, click on the "Change Me" button and make sure it's in "Repeat back to me" mode, and for call options, select "Execution argument". Then, we save the workflow.

![Shuffle Workflow Settings](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/2024-06-04%2021_41_05-Workflow%20-%20SOC%20Automation%20Lab.png)

On our Wazuh manager CLI, we need to tell Wazuh that we are going to connect to Shuffle.
We can do this by adding what is called an "integration" tag in the Ossec configuration.
```
nano /var/ossec/etc/ossec.conf
```

And here, we add this integration:
```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_0af8a049-f2cb-420b-af58-5ebc3c40c7df</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

Because instead of `<level>`, we want to send the alerts based on the rule ID, we will change the `<level>` tag with `<rule_id>100002</rule_id>`.

![Wazuh Shuffle Integration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604225725.png)

And of course, we restart the service:
```
systemctl restart wazuh-manager.service
```

Now we will regenerate the Mimikatz telemetry on our Windows machine again.

After we start Mimikatz again, we head over to Shuffle and click on our webhook ("Wazuh-Alerts") and click "Start".

![Shuffle Webhook Start](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604230243.png)

And we have a run alert.

Now we will build a workflow for Mimikatz, which will only work for this demo, but the same concepts can be applied to other cases. With this example, we can customize other alerts and automations.

**Workflow:**
1. Mimikatz alert sent to Shuffle
2. Shuffle receives Mimikatz alert / extract SHA256 hash from file
3. Check reputation score with VirusTotal
4. Send details to TheHive to create an alert
5. Send an email to the SOC analyst to begin the investigation

When we look at the return values for the hashes, we notice that they are appended by their hash type, like `sha1=hashvalue`, etc.

If we wanted to automate this, we would need to parse out the hash value itself because if we don't do this step, the entire value, including `sha1=`, will be sent over to VirusTotal to check, which will be nonsense. We only want to send the hash value.

To do this, we click on the "Change Me" icon, and now, instead of the "Repeat back to me" option, we select "Regex capture group".
After that, in the "Input data", we select the "hashes" option.
And finally, for the "Regex" tab, we will need to put a regex to parse the SHA256 value of the hash.
To parse the SHA256 value, the regex is `SHA256=([0-9A-Fa-f]{64})`.
We enter this in the "Regex" tab and save our workflow.

![Shuffle Regex](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604234504.png)

After we click on the running man button, which is the "Show execution" button, we see that our hash value is extracted.

![Extracted Hash Value](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604234729.png)

Now that we've actually parsed the hash value for the file, we can automatically send it to VirusTotal and check the reputation score.
The next thing we want to do is utilize the VirusTotal API so we can automatically ask VirusTotal about the hashes and return the values to us.
And in order to utilize the API, we need to create an account with VirusTotal.

![VirusTotal Account](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240604235908.png)

We copy our API key and come back to Shuffle, click on the "Apps" and search for "VirusTotal". We pull "VirusTotal" to the workflow, and it will automatically connect.

![VirusTotal App](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605000230.png)

For the API key, you can either enter it on the right side or click "Authenticate VirusTotal v3" and do it there.

![VirusTotal Authentication](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605000358.png)

Now, after we change the "ID" field to the "SHA256Regex" that we created, we save our workflow and rerun it.

![VirusTotal ID](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605001826.png)

We see that VirusTotal now has results.

![VirusTotal Results](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605001925.png)

When we expand the results, there is a lot of information, and we see that 67 scanners had detected this file as malicious.

![VirusTotal Detection](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605002209.png)

To recap, so far, we set up our SOAR platform to receive our Wazuh alert, then we performed regex to parse out the SHA256 hash, and then we used VirusTotal to check its reputation.
Now, for the next step, we will send the details over to TheHive so TheHive can create an alert for case management.

We search for "TheHive" in the "Apps" in Shuffle and drag it into our workflow.
If we recall, we can connect to TheHive with the IP address of TheHive that we created on DigitalOcean and port number 9000.

![TheHive Login](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605112834.png)

```
http://143.198.56.201:9000/login
```

By default, the login is `admin@thehive.local`, and the password is `secret`.
After we log in, we will create a new organization and user for this organization.

![TheHive Organizations](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605113123.png)

And for this organization, we add new users with different profiles if we like.

![TheHive Users](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605113317.png)

Then, we set new passwords for these users.
Now, for our SOAR users that we created for Shuffle, we want to create an API key.

![TheHive API Key](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605113655.png)

We create an API key and put it somewhere safe. We will be using it to authenticate Shuffle.
Now let's log out from the admin account and log in from one of the user accounts.
When we log in, we see a page like this. Of course, we don't have a case right now.

![TheHive Dashboard](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605115228.png)

Now let's head over to Shuffle and configure it to work with TheHive.

![Shuffle TheHive](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605115401.png)

Here, we click on the orange "Authenticate TheHive" button, and we enter our API key that we created and saved from TheHive.
And for the URL part, we want to enter the public IP of TheHive with the port number.

![Shuffle TheHive Authentication](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605115759.png)

Next, we click on "TheHive" under the "Find actions", and we want to select "Create alerts".
Now, we need to set the JSON payload so TheHive can get the alerts. Here is the specific example payload for this lab and for Mimikatz:

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

To set this payload, we go to the "Body" part of this page and expand it.

![Shuffle TheHive Body](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605141313.png)

And there, we can set the payload on the left side and test the output on the right side:

![Shuffle TheHive Payload](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605145351.png)

Now, when we save our workflow and rerun it, right there, we see that an alert pops up in our TheHive dashboard.

![TheHive Alert](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605143428.png)

If you have a firewall set up for TheHive in your cloud provider, you should add a new inbound rule to set the port range of 9000 so any source can access TheHive from port 9000.
And when we click on the alert, we see a page like this:

![TheHive Alert Details](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605145839.png)

To have more information about the alert, you can customize any space in TheHive's JSON payload.
For instance, let's create a more extensive summary.
On Shuffle, I click on the "Show Body" button and see the spaces for all JSON payloads.

Here, in the summary, let's say I want to show the command line that is related to this alert.
You can add anything here, depending on what you want.
Actually, I decided to set the technique and command line for the summary part:

![Shuffle TheHive Summary](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605165035.png)

You can find what to write in these lines from the body part of TheHive in Shuffle.

![Shuffle TheHive Body](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605165143.png)

After we save and rerun the workflow, we see our new alert with more information.

![TheHive Alert Updated](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605164956.png)

Now, our next step is to send an email to our analyst containing relevant information.
In our Shuffle workflow, we find "Email" in the "Apps" and connect VirusTotal to our email.

![Shuffle Email](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605165431.png)

Here, you can use any email you want to send the alert with the necessary information about the event or subject line.

![Shuffle Email Configuration](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605170704.png)

We save our workflow and rerun it.

![Shuffle Workflow Final](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605170809.png)

This is our final workflow.
And when we check our email, we see that it is working.

![Email Received](https://github.com/uruc/SOC-Automation-Lab/blob/main/images/Pasted%20image%2020240605170915.png)

This concludes the setup and configuration of the SOC Automation Lab, integrating Wazuh, TheHive, and Shuffle for automated event monitoring, alerting, and incident response. With this foundation, you can further customize and expand the automation workflows to suit your specific SOC requirements.
