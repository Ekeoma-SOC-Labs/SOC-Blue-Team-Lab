# **Domain Controller (DC01) Setup & Active Directory Configuration**
### **Goal of This Component**

The purpose of this component is to deploy a Windows Server 2019 Domain Controller that provides:

- Centralized authentication

- Identity and access management

- DNS services

- Group Policy enforcement

This Domain Controller represents a real enterprise Active Directory environment, which is critical for realistic SOC monitoring, detection engineering, and attack simulations.

### **Environment Details**

- OS: Windows Server 2019 (64-bit)

- Role: Domain Controller (AD DS + DNS)

- Hostname: DC01

- Domain Name: EKE.local

- Static IP (Host-only): 192.168.56.10

- DNS Server: 127.0.0.1

## **Step - 1. VirtualBox Network Configuration**
### **Network Design**

DC01 is configured with two network adapters:

- Adapter 1	    NAT	          Internet access (Windows Updates, downloads)

- Adapter 2   	Host-only	    Internal SOC lab communication

### **Expected IP Addressing**

NAT Adapter: DHCP (10.x.x.x)

Host-only Adapter: Static IP → 192.168.56.10


## **Step - 2. Static IP Configuration**

A Domain Controller must always use a static IP address to ensure DNS and authentication stability.

### **Steps**

1. Open Network & Internet Settings

2. Click Change adapter options

3. Open Host-only Adapter Properties

4. Configure IPv4 manually:

- IP Address: 192.168.56.10

- Subnet Mask: 255.255.255.0

- Default Gateway: (leave blank)

- DNS Server: 127.0.0.1

## **Step - 3 Rename the Server**

The server was renamed to clearly identify its role.

- New Hostname: DC01

After renaming, the system was restarted.

## **Step - 4. Install Active Directory Domain Services (AD DS)**
### **Installation Steps**

1. Open Server Manager
2. Click Add Roles and Features
3. Select:

- Active Directory Domain Services

- DNS Server (auto-selected)

4. Complete installation

## **Step - 5. Promote Server to Domain Controller**

After AD DS installation, the server was promoted to a Domain Controller.

### **Promotion Configuration**

- Deployment: Add a new forest

- Root Domain Name: EKE.local

- DNS: Enabled

- DSRM Password: Set securely

The server rebooted automatically after promotion.

## **Step - 6. Verify Domain Services**

After reboot, login was performed using:

EKE\Administrator

### **Service Verification Command**

Get-Service adws,dns,ntds,kdc

All services were confirmed Running.

## **Step - 7. Organizational Unit (OU) Structure**

To mirror enterprise best practices, the following OU structure was created:

EKE.local
│
├── _Admins
├── _Users
├── _Computers
├── _Servers
└── _Groups

## **Step - 8. Domain User Creation**

Test and SOC-related user accounts were created under the _Users OU:

- WIN10User

- SOCAnalyst

- ITSupport

These accounts are used for login simulation, log generation, and detection testing.

## **Step - 9. Join Windows 10 Endpoint to Domain**

The Windows 10 endpoint (WIN10-CL01) was joined to the domain.

### **Steps**

1. Open System Properties
2. Click Rename this PC (Advanced)
3. Select Domain
4. Enter: EKE.local

Authenticate with domain admin credentials

## **Step - 10. Group Policy – Security Baseline**

A basic security hardening GPO was created.

### **GPO Name**
Baseline-Security

### **Applied To**

- EKE.local domain

## **Configured Policies**

### **Password Policy**

- Minimum length: 12

- History: 24

- Complexity: Enabled

- Maximum age: 60 days

### **Account Lockout**

- 5 failed attempts

- Lockout duration: 15 minutes

## **Step - 11. DNS and Replication Verification**
### **Commands Used in poweshell**
- ipconfig /all
- nslookup dc01
- nslookup eke.local

### **Expected Result**

- DNS resolves to 192.168.56.10

- Domain name resolves correctly

## **Step - 12. Final Health Checks**

### **Additional validation steps:**

powershell - dcdiag

- Checked Directory Services event logs

- Verified WIN10-CL01 appears in _Computers OU

## **SOC & Real-World Relevance**

In real enterprise environments, Domain Controllers are the primary source of security telemetry, including:

- Authentication events

- Privilege escalation attempts

- Lateral movement detection

- Policy violations

This DC01 setup enables realistic SOC detections using Windows Security logs, PowerShell logs, and Active Directory telemetry.


## **Ekeoma Eneogwe**

Cybersecurity Analyst — SOC / Blue Team

Active Directory • Detection Engineering • SIEM Operations
