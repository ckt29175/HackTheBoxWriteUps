# Zipper (Writeup not finished)

This is a write up on the HTB machine, Zipper. I have seen a few methods people used to obtain the initial user but this is the method I used.


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
 By doing a quick Google search, we are able to get a general idea of what the port is used for which is `Zabbix-Agent`:
 https://www.speedguide.net/port.php?port=10050
 
 Next, we look at the HTTP service. On the default page of the web server, it is a default Apache2 Ubuntu page.
 Trying to brute force the directory using default Dirb wordlist and seclist's `big.txt` resulted in nothing significant. By using     the information we have gotten on `10050`, the directory `zabbix` was attempted and found a login page: 
 
 ![Image](https://i.imgur.com/G7IOBIR.png)

 Default credentials were attempted on the login pannel, however, none of them were valid. 
 We are able to login as a "guest" user. Using CewL, a wordlist was created.
 ```
 [root:~]# cewl http://10.10.10.108/zabbix/zabbix.php\?action\=dashboard.view -H cookie:PHPSESSID=8b2a9bpfd5bvf5jk9s8lqfq9rl -m 5 -d 4 > zabbixwordlist.txt
```
To explain this syntax, we are able to pass a cookie in the header field so CewL scrapes words as the user "guest". The cookie was found by intercepting using Burp when logging in via "guest":
![alt text](https://i.gyazo.com/0fcc5ac903ffefe902e1a88f45926c1b.png)

In a more effiecnt approach, we are able to make a wordlist ourselves:
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




