#!/usr/bin/env python2
import lib
from lib.external_scan import external_scan
from lib.external_scan import scanport
from lib.external_scan import openports
from lib.external_scan import bcolors
import sys

target = str(sys.argv[1:])
target = target.replace("[","")
target = target.replace("]","")
target = target.replace(",","")
target = target.replace("'","")

print(bcolors.OKGREEN + '__________      ___.   ____        ')
print(bcolors.OKGREEN + '\______   \ ____\_ |__/_   | ____  ')
print(bcolors.OKGREEN + ' |       _//  _ \| __ \|   |/    \ ')
print(bcolors.OKGREEN + ' |    |   (  (_) ) \_\ \   |   |  \\')
print(bcolors.OKGREEN + ' |____|_  /\____/|___  /___|___|  /')
print(bcolors.OKGREEN + '        \/           \/         \/ ')
print(bcolors.OKGREEN + '      The Pentesters Sidekick      ')
print(bcolors.OKGREEN + '          By: StingraySA           ')
print(bcolors.OKGREEN + '-----------------------------------' + bcolors.ENDC)

# Initialise everything for the external scan
external_scan(target)

# Perform the external scan on all open ports
x = 0
if len(openports) != '':
	while x < len(openports):
		scanport(openports[x], target)
		x += 1
	scanport('down', target) # Run all the generic scans that are not port specific
else:
	print('Sorry, there''s no ports to scan on this server')
