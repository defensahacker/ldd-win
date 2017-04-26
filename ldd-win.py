#!/usr/bin/python
#
# ldd-win.py
#
# A similar Linux ldd command for EXE files... for DLL hijacking prevention or exploitation
#
# When invoking LoadLibrary or CreateProcess or ShellExecute on Windows environments
# a fully qualified path must be specified. Otherwise the search path goes as follows:
#
# 1) directory from which the application loaded
# 2) system directory
# 3) 16-bit system directory
# 4) Windows directory
# 5) current directory
# 6) directories listed in the PATH
#
# (c) spinfoo
#

import pefile
import sys

verbose= False

if len(sys.argv) == 3 and sys.argv[2] == "-v":
  verbose= True
elif len(sys.argv) != 2:
  print "usage: %s file.exe [-v]" %sys.argv[0]
  sys.exit(1)

pe=  pefile.PE(sys.argv[1])

# If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
pe.parse_data_directories()

print "PE Exports"
print "-"*80
for entry in sorted(pe.DIRECTORY_ENTRY_IMPORT, cmp= lambda x,y: cmp(str.lower(x.dll[0]), str.lower(y.dll[0]))):
  print "\t%s\t\t\t[ # imported functions: %02d]" %(str.upper(entry.dll),len(entry.imports))
  if verbose:
    for imp in entry.imports: print "\t\t%s (%s)" %(imp.name, hex(imp.address))

# Uncomment next line for extra verbose mode:
# print pe.dump_info()

sys.exit(0)

