#!/usr/bin/env python2
from external_scan import external_scan
from external_scan import scanport
from external_scan import openports
import sys

target = str(sys.argv[1:])
target = target.replace("[","")
target = target.replace("]","")
target = target.replace(",","")
target = target.replace("'","")

external_scan(target)

x = 0
if len(openports) != '':
	while x < len(openports):
		scanport(openports[x], target)
		x += 1
	scanport('down', target) # Run all the generic scans that are not port specific
else:
	print('Sorry, there''s no ports to scan on this server')
