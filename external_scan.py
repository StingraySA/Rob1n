#!/usr/bin/env python2
#Requires
# pip install wafw00f

import re
import requests
import sys
import subprocess
from collections import Counter

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

openports = []

scans = ['nmap -p80 --script http-security-headers -Pn <>', 80,
         'nmap -p443 --script http-security-headers -Pn <>', 443,
         'nmap -p443 --script ssl-heartbleed -Pn --script-args vulns.showall <>', 443,
         'nmap -p443 --script ssl-poodle -Pn <>', 443,
         'nmap -p443 --script ssl-ccs-injection -Pn <>', 443,
         'nmap -p443 --script ssl-enum-ciphers -Pn <>', 443,
         'nmap -p443 --script ssl-dh-params -Pn <>', 443,
         'nmap -p80 --script=http-iis-webdav-vuln -Pn <>', 80,
         'nmap -p80 --script=http-iis-webdav-vuln -Pn <>', 8080,
         '<>/%7C~.aspx', 'down',
         '<>/wp-admin', 'down',
         '<>/user', 'down',
         '<>/administrator', 'down',
         '<>/elmah.axd', 'down',
         '<>/robots.txt', 'down',
         '<>/sitemap.xml', 'down',
         'wafw00f http://<>', 80,
         'nmap --script http-aspnet-debug <>', 80,
         'nmap -p 80 --script http-enum <>', 80,
         'nmap -p 443 --script http-enum <>', 443,
         'nmap -p 80 --script http-csrf <>', 80,
         'nmap -p 443 --script http-csrf <>', 443,
         'nmap -p 80 --script http-dombased-xss <>', 80,
         'nmap -p 443 --script http-dombased-xss <>', 443,
         'nmap -p 80 --script http-iis-short-name-brute <>', 80,
         'nmap -p 443 --script http-iis-short-name-brute <>', 443,
         'nmap -p 80 --script http-sitemap-generator <>', 80,
         'nmap -p 443 --script http-sitemap-generator <>', 443,
         'nmap -p 80 --script http-sql-injection <>', 80,
         'nmap -p 443 --script http-sql-injection <>', 443,
         'nmap -p 80 --script http-xssed <>', 80,
         'nmap -p 80 --script http-xssed <>', 443,
         'curl -L -c - http://<>', 80,
        ]

headers = [bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking if XSS Protection Header is present on HTTP' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking if XSS Protection Header is present on HTTPS' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for Heartbleed Vulnerability' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for POODLE Vulnerability' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for CSS Injection' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for Weak / Broken Ciphers' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for Diffie-Hellman on SSL and TLS' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for IIS WebDAV' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for IIS WebDAV' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for ASP.Net Stack Errors' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for WordPress Installation' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for Drupal Installation' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for Joomla Installation' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for Elmah Installation' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for Robots.txt' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for Sitemap.xml' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for Web Application Firewall' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking status of ASP.NET Debug' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Looking for files / directories of interest' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Looking for files / directories of interest' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for possible CSRF vulnerabilities' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for possible CSRF vulnerabilities' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for possible DOM based XSS' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for possible DOM based XSS' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for IIS short name brute' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for IIS short name brute' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Generating a quick sitemap' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Generating a quick sitemap' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for possible SQLi points' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking for possible SQLi points' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking if site is listed on xssed.com' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking if site is listed on xssed.com' + bcolors.ENDC,
           bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Checking Cookies' + bcolors.ENDC,
          ]

# These are the string to search for in the output of the tool if it fails
search_strings = ['X-XSS-Protection: 0',
                  'X-XSS-Protection: 0',
                  'State: VULNERABLE',
                  'SSL POODLE information leak',
                  'State: VULNERABLE',
                  'warnings:',
                  'State: VULNERABLE',
                  'WebDAV is ENABLED',
                  'WebDAV is ENABLED',
                  'Stack Trace:', # Download
                  '404', # Download
                  '404', # Download
                  '404', # Download
                  '404', # Download
                  '404', # Download
                  '404', # Download
                  'seems to be behind a WAF',
                  'DEBUG is enabled',
                  'http-enum:',
                  'http-enum:',
                  'following possible CSRF',
                  'following possible CSRF',
                  'potential DOM based XSS',
                  'potential DOM based XSS',
                  'Exploitable',
                  'Exploitable',
                  'Directory structure:',
                  'Directory structure:',
                  'Possible sqli for queries:',
                  'Possible sqli for queries:',
                  'xssed.com found the following',
                  'xssed.com found the following',
                  'html',
                 ]

        # These are the Pass or Fail Error Messages for each Command
        # String Not Found, String Found
messages = ['PASS', 'FAIL',
            'PASS', 'FAIL',
            'PASS', 'FAIL',
            'PASS', 'FAIL',
            'PASS', 'FAIL',
            'PASS', 'FAIL',
            'PASS', 'FAIL',
            'DISABLED', 'ENABLED :80', #WebDAV:80
            'DISABLED', 'ENABLED :8080', #WebDAV:8080
            'ENABLED', 'DISABLED', #ASP.Net Stack Errors ( Reverse the logic for this one )
            'INSTALLED', 'NOT INSTALLED', #Wordpress
            'INSTALLED', 'NOT INSTALLED', #Drupal
            'INSTALLED', 'NOT INSTALLED', #Joomla
            'INSTALLED', 'NOT INSTALLED', #Elmah
            'FOUND', 'NOT FOUND',
            'FOUND', 'NOT FOUND',
            'NONE', 'DETECTED',
            'DISABLED', 'ENABLED',
            'NOT FOUND', 'FOUND :80',
            'NOT FOUND', 'FOUND :443',
            'NONE', 'FOUND :80',
            'NONE', 'FOUND :443',
            'NONE', 'FOUND :80',
            'NONE', 'FOUND :443',
            'NONE', 'SUCCESS :80',
            'NONE', 'SUCCESS :443',
            'FAILED', 'SUCCESS :80',
            'FAILED', 'SUCCESS :443',
            'NONE', 'SUCCESS :80',
            'NONE', 'SUCCESS :443',
            'NOT FOUND', 'FOUND :80',
            'NOT FOUND', 'FOUND :443',
            'FAILED', 'SUCCESS :80',
           ]

def external_scan(target = ''):
        debug_filename = 'debug.log'
        output_filename = 'Rob1n-' + target + '.log'

        debug_file = open( debug_filename, 'wb' )
        output_file = open( output_filename, 'wb' )
        output = ''

        print(bcolors.OKGREEN + '__________      ___.   ____        ')
        print(bcolors.OKGREEN + '\______   \ ____\_ |__/_   | ____  ')
        print(bcolors.OKGREEN + ' |       _//  _ \| __ \|   |/    \ ')
        print(bcolors.OKGREEN + ' |    |   (  (_) ) \_\ \   |   |  \\')
        print(bcolors.OKGREEN + ' |____|_  /\____/|___  /___|___|  /')
        print(bcolors.OKGREEN + '        \/           \/         \/ ')
        print(bcolors.OKGREEN + '      The Pentesters Sidekick      ')
        print(bcolors.OKGREEN + '          By: StingraySA           ')
        print(bcolors.OKGREEN + '-----------------------------------' + bcolors.ENDC)

        # Do a quick port scan of the target to see what we can test
        sys.stdout.write(bcolors.BOLD+ '[*] ' + bcolors.ENDC + bcolors.HEADER + 'Doing a Port Scan to see what we can test\n' + bcolors.ENDC)
        sys.stdout.flush()
        output = subprocess.check_output( '{}'.format( 'nmap -Pn -sV -open ' + target ), shell = True )
        debug_file.write(output)
        screenout = output.split('\n', 7)[-1]
        screenout = "\n".join(screenout.split("\n")[0:-3])
        output_file.write('######################################################\n')
        output_file.write('Port Scan\n')
        output_file.write('######################################################\n')
        output_file.write(screenout);
        if re.search('80/tcp' ,output):
        	openports.append(80)
        if re.search('443/tcp', output):
        	openports.append(443)

        portscan = output.split('\n', 7)[-1]
        portscan = "\n".join(portscan.split("\n")[0:-3])
        sys.stdout.write(bcolors.OKBLUE + portscan + '\n' + bcolors.ENDC)

def scanport(port = 0, target = ''):
        debug_filename = 'debug.log'
        output_filename = 'Rob1n-' + target + '.log'
        debug_file = open( debug_filename, 'a' )
        output_file = open( output_filename, 'a' )
        output = ''
    	i = 0
    	a = 0
    	while i < len(scans):
    		if scans[i+1] == port:
    			sys.stdout.write(headers[a])
    			sys.stdout.flush()
    			command = str.replace(scans[i], "<>", target)
    			if port != 'down':
    				output = subprocess.check_output( '{}'.format( command ), stderr=subprocess.STDOUT, shell = True )
    				debug_file.write(output)
    				screenout = output.split('\n', 7)[-1]
    				screenout = "\n".join(screenout.split("\n")[0:-2])
    				output_file.write(headers[a])
    				if re.search(search_strings[a] ,output):
    					sys.stdout.write(bcolors.FAIL + ' [' + messages[i+1] + ']\n' + bcolors.ENDC)
    					output_file.write(' [' + messages[i+1] + ']\n')
    				else:
    					sys.stdout.write(bcolors.OKGREEN + ' [' + messages[i] + ']\n' + bcolors.ENDC)
    					output_file.write(' [' + messages[i] + ']\n')
    				if a == 5: #All the SSL Errors
    					if re.search('vulnerable to SWEET32 attack', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + '64-bit block cipher 3DES vulnerable to SWEET32 attack\n' + bcolors.ENDC)
    						output_file.write('[!] 64-bit block cipher 3DES vulnerable to SWEET32 attack\n')
    					if re.search('Broken cipher RC4', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'Broken cipher RC4 is deprecated by RFC 7465\n' + bcolors.ENDC)
    						output_file.write('[!] Broken cipher RC4 is deprecated by RFC 7465\n')
    					if re.search('Ciphersuite uses MD5', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'Ciphersuite uses MD5 for message integrity\n' + bcolors.ENDC)
    						output_file.write('[!] Ciphersuite uses MD5 for message integrity\n')
    					if re.search('signature: SHA1', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'Weak certificate signature: SHA1\n' + bcolors.ENDC)
    						output_file.write('[!] Weak certificate signature: SHA1\n')
    					if re.search('CBC-mode cipher in SSLv3 (CVE-2014-3566)', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'CBC-mode cipher in SSLv3 (CVE-2014-3566)\n' + bcolors.ENDC)
    						output_file.write('[!] CBC-mode cipher in SSLv3 (CVE-2014-3566)\n')
    					if re.search('Certificate RSA exponent is 1', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'Certificate RSA exponent is 1\n' + bcolors.ENDC)
    						output_file.write('[!] Certificate RSA exponent is 1\n')
    					if re.search('Insecure certificate signature:', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'Insecure certificate signature\n' + bcolors.ENDC)
    						output_file.write('[!] Insecure certificate signature\n')
    					if re.search('lower strength than certificate key', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'Key exchange of lower strength than certificate key\n' + bcolors.ENDC)
    						output_file.write('[!] Key exchange of lower strength than certificate key\n')
    				if a == 18 or a == 19 or a == 20 or a == 21 or a == 26 or a == 27 or a == 28 or a == 29 or a == 30 or a == 31: # Show the scan results
    					if re.search(search_strings[a] ,output):
    						sys.stdout.write(bcolors.FAIL + screenout + '\n' + bcolors.ENDC)
    						output_file.write(screenout)
    				if a == 32:
    					if not re.search('HttpOnly', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'HTTPOnly flag not set\n' + bcolors.ENDC)
    						output_file.write('[!] HTTPOnly flag not set\n')
    					if not re.search('Secure', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'Secure flag not set\n' + bcolors.ENDC)
    						output_file.write('[!] Secure flag not set\n')
    					if not re.search('HostOnly', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'HostOnly flag not set\n' + bcolors.ENDC)
    						output_file.write('[!] HostOnly flag not set\n')
    					if not re.search('sameSite', output):
    						sys.stdout.write(bcolors.FAIL + bcolors.BOLD+ '[!] ' + bcolors.ENDC + bcolors.FAIL + 'sameSite flag not set\n' + bcolors.ENDC)
    						output_file.write('[!] sameSite flag not set\n')

    			elif port == 'down':
    				if a == 9:
    					#Reverse Logic Finds
    					ret = requests.get('http://' + command)
    					if re.search(search_strings[a], ret.text):
    						sys.stdout.write(bcolors.FAIL + ' [' + messages[i] + ' :80]\n' + bcolors.ENDC)
    						output_file.write(headers[a] + ' [' + messages[i] + ' :80]\n')
    					else:
    						sys.stdout.write(bcolors.OKGREEN + ' [' + messages[i+1] + ' :80]\n' + bcolors.ENDC)
    						output_file.write(headers[a] + ' [' + messages[i+1] + ' :80]\n')

                        		sys.stdout.write(headers[a])
                        		ret = requests.get('https://' + command)

                        		if re.search(search_strings[a], ret.text):
    						sys.stdout.write(bcolors.FAIL + ' [' + messages[i] + ' :443]\n' + bcolors.ENDC)
    						output_file.write(headers[a] + ' [' + messages[i] + ' :443]\n')
    					else:
    						sys.stdout.write(bcolors.OKGREEN + ' [' + messages[i+1] + ' :443]\n' + bcolors.ENDC)
    						output_file.write(headers[a] + ' [' + messages[i+1] + ' :443]\n')
    				else:
    					ret = requests.get('http://' + command)
    					if not re.search(search_strings[a], ret.text):
    						sys.stdout.write(bcolors.FAIL + ' [' + messages[i] + ' :80]\n' + bcolors.ENDC)
    						output_file.write(headers[a] + ' [' + messages[i] + ' :80]\n')
    					else:
    						sys.stdout.write(bcolors.OKGREEN + ' [' + messages[i+1] + ' :80]\n' + bcolors.ENDC)
    						output_file.write(headers[a] + ' [' + messages[i+1] + ' :80]\n')
    					sys.stdout.write(headers[a])
                        		ret = requests.get('https://' + command)
    					if not re.search(search_strings[a], ret.text):
    						sys.stdout.write(bcolors.FAIL + ' [' + messages[i] + ' :443]\n' + bcolors.ENDC)
    						output_file.write(headers[a] + ' [' + messages[i] + ' :443]\n')
    					else:
    						sys.stdout.write(bcolors.OKGREEN + ' [' + messages[i+1] + ' :443]\n' + bcolors.ENDC)
    						output_file.write(headers[a] + ' [' + messages[i+1] + ' :443]\n')

    			debug_file.flush()
    			output_file.flush()
    		i += 2
    		a += 1

        debug_file.close()
        output_file.close()
