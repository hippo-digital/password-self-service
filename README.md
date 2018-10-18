# Installation Instructions

## Server (Back-end) Install

### Download and install these components

* Python 3.6.2 64-bit (ensure you get the amd64 one)
* Git (latest version)
* PyWin32 https://sourceforge.net/projects/pywin32/files/pywin32/Build%20221/pywin32-221.win-amd64-py3.6.exe/download


### Install source

````
mkdir C:\git
cd C:\git
git clone https://github.com/hippodigital/password-self-service.git


pip install requests pyyaml twilio https://github.com/zakird/pyad/archive/master.zip
````

### Configuration

Update the config file to reflect local environment

The file is: C:\git\password-self-service\password_reset_backend\config.yml

````
---
  directory:

    # Update to reflect the
    dn: CN=Users,DC=hd,DC=local
    fqdn: hd.local

  frontend:
    address: https://10.211.55.2:5000

  sms:
    message: "A reset code has been requested for your account.\n\nIf this was in error contact the service desk on 0113 235 3315.\n\nYour reset code is %s"
    organisation_shortname: RothICT
    twilio_sid: ACf5e81dd572ad916b9dbd6d1883e755ae
    twilio_authcode: b3ae4c2f616c9f9529aba41ce219cfd6

  redis:
    address: 127.0.0.1
    port: 6379
    db: 0
````

### Deploy Front-end on Ubuntu

**Notes:**

* It is recommended that Canonical.UbuntuServer-16.04-LTS is used as the VM image
* The VM should be configured to allow ports 22, 443 and 444 for ingress

1. SSH to the VM
2. Install the necessary components using `apt-get`

````
sudo apt-get Update
sudo apt-get install git python make

sudo apt-get install software-properties-common
sudo apt-add-repository --yes --update ppa:ansible/ansible
sudo apt-get install ansible
````
3. Generate and configure keypair for ansible

````
ssh-keygen -t rsa
# Press return for all questions

cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
````

4. Install Password Reset Front-end

````
cd ~/password-self-service/ansible
ansible-playbook -i inventories/main --limit local install_frontend.yml -u azureuser --sudo --private-key=~/.ssh/id_rsa
````

5. Configure for local settings

Amend the nginx configuration for the UI:

````
sudo vim /etc/nginx/sites-available/hippo-pwd-ui
````

Replace all instances of `pwd.hippo.digital` with the desired hostname, e.g. `myorg.myidentity.care`

````
sudo vim /etc/nginx/sites-available/hippo-pwd-receiver
````

Replace all instances of `pwd.hippo.digital` with the desired hostname, e.g. `myorg.myidentity.care`

6. Add SSL certificate

````
sudo vim /etc/hippo-pwd/rotherham.myidentity.care.key
# Paste the content of the private key, and save

sudo vim /etc/hippo-pwd/rotherham.myidentity.care.pem
# Paste the content of the certificate, and save
````

Reset the host

````
sudo init 6
````
