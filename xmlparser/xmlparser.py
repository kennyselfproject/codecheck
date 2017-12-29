#!/usr/bin/python
 
import xml.sax
import os
import sys
import pdb
 
class XMLHandler(xml.sax.ContentHandler):
   def __init__(self):
      self.KeyArray = ["file", "line", "id", "subid", "severity", "msg", 
                       "web_identify", "content"]
      self.RuleArray = {
         # Critical sub types
         "dereferenceIfNull"         :"Critical",
         "explicitNullDereference"   :"Critical",
         "checkNullDefect"           :"Critical",
         "arrayIndexOutOfBounds"     :"Critical",
         "arrayIndexThenCheck"       :"Critical",
         "arrayIndexCheckDefect"     :"Critical",
         "InvalidVarArgs"            :"Critical",

         # Serious sub types
         "dereferenceAfterCheck"     :"Serious",
         "funcRetNullStatistic"      :"Serious",
         "dereferenceBeforeCheck"    :"Serious",
         "invalidDereferenceIterator":"Serious",
         "negativeIndex"             :"Serious",
         "bufferAccessOutOfBounds"   :"Serious",
         "funcRetLengthAsIndex"      :"Serious",
         "stlOutOfBounds"            :"Serious",
         "ZeroDivision"              :"Serious",
         "memsetZeroBytes"           :"Serious",
         "suspiciousArrayIndex"      :"Serious",
         "suspiciousfor"             :"Serious",
         "wrongvarinfor"             :"Serious",
         "invalidIterator"           :"Serious",
         "CompareDefectInFor"        :"Serious",
         "uninitstring"              :"Serious",
         "uninitvar"                 :"Serious",
         "possibleUninitvar"         :"Serious",
         "uninitPtr"                 :"Serious",
         "possibleUninitPtr"         :"Serious",
         "uninitMemberInCtor"        :"Serious",
         "possibleUninitStruct"      :"Serious",
         "UninitStruct"              :"Serious",
         "possibleUninitMemberInCtor":"Serious",
         
         # Warning sub types
         "funcRetNull"               :"Warning",
         "memleak"                   :"Warning",
         "memleakOnRealloc"          :"Warning",
         "resourceLeak"              :"Warning",
         "deallocDealloc"            :"Warning",
         "deallocuse"                :"Warning",
         "mismatchAllocDealloc"      :"Warning",
         "mismatchSize"              :"Warning",
         "virtualDestructor"         :"Warning",
         "incrementboolean"          :"Warning",
         "moduloAlwaysTrueFalse"     :"Warning",
         "SizeofForNumericParameter" :"Warning",
         "SizeofForArrayParameter"   :"Warning",
         "SizeofForPointerSize"      :"Warning",
         "sizeofsizeof"              :"Warning",
         "UnsignedDivision"          :"Warning",
         "NegativeBitwiseShift"      :"Warning",
         "autovar"                   :"Warning",
         "Danglingpointer"           :"Warning",
         "NestedLoop"                :"Warning",
         "unConditionalBreakinLoop"  :"Warning",
         "IfCondition"               :"Warning",
         "strPlusChar"               :"Warning",
         "bitwiseOnBoolean"          :"Warning",
         "ComparisonOfBoolWithInt"   :"Warning",
         "ComparisonOfBoolWithBool"  :"Warning",
         "ComparisonWithBool"        :"Warning",
         "assignIf"                  :"Warning",
         "oppositeInnerCondition"    :"Warning",
         "incorrectLogicOperator"    :"Warning",
         "clarifyCondition"          :"Warning",
         "StlMissingComparison"      :"Warning",
         "stlSortCheck"              :"Warning",
         "SwitchNoBreakUP"           :"Warning",
         "NoFirstCase"               :"Warning",
         "RecursiveFunc"             :"Warning",
         "UnintentionalOverflow"     :"Warning",
         "duplicateBranch"           :"Warning",
         "DuplicateExpression"       :"Warning",
         "selfAssignment"            :"Warning",
         "duplicateIf"               :"Warning",
         "STLFindError"              :"Warning",
         "unsafeFunctionUsage"       :"Warning",
         "uninitMemberVar"           :"Warning",

         # Information sub types
         "PreciseComparison"         :"Information",
         "Unsignedlessthanzero"      :"Information",
         "assignmentInAssert"        :"Information",
         "suspiciousSemicolon"       :"Information",
         "SuspiciousPriority"        :"Information",
         "FuncReturn"                :"Information",
         "BoolFuncReturn"            :"Information",
         "SwitchNoDefault"           :"Information",
         "SignedUnsignedMixed"       :"Information",
         "redundantCondition"        :"Information"
         }
 
   def readfile(self, srcfilepath):
      # read srouce file
      srcfileobj = open(srcfilepath, 'r')
      fsize = os.path.getsize(srcfilepath)
      filebuf = srcfileobj.read(fsize);
      srcfileobj.close()

      return filebuf

   def analyzeRowBuffer(self, row, length):
      attrs = {}
      # strstat [0: scan key, 1: scan key end, 2: string start, 3: string end]
      strstat = 0 
      curoff = 0
      value = ""
      # pdb.set_trace()
      for off in range(0, length) : 
         if row[off] == '=' and strstat == 0:
            key = row[curoff : off]
            curoff = off + 1
            strstat = 1
         elif row[off] == '"':
            if strstat == 1:
               curoff = off
               strstat = 2
            elif strstat == 2:
               value = row[curoff+1 : off]
               attrs[key] = value
               strstat = 3
         elif strstat == 3 and row[off] != ' ':
            strstat = 0
            curoff = off

      return attrs
               

   def analyzeBuffer(self, filebuf, level):
      start = filebuf.find("<error ") + 7
      end = filebuf.find("</results>")

      errorbuf = filebuf[start : end]
      errors = errorbuf.split("<error ")

      results = []

      # pdb.set_trace()
      for error in errors :
         rowstart = error.find("file=")
         rowend = error.find("/>")
         row = error[rowstart : rowend]
         length = rowend - rowstart
         attrs = self.analyzeRowBuffer(row, length)
         subtype = attrs["subid"]
         curlevel = self.RuleArray[subtype]
         if curlevel == level :
            row = {}
            for key in self.KeyArray:
               row[key] = attrs[key]
            results += [row]
         

      return results

   def outputFile(self, results, descfilepath):
      descfileobj = open(descfilepath, 'w')
      descfileobj.write('<?xml version="1.0" encoding="UTF-8"?>\n<results>\n\n');
      # pdb.set_trace() 
      for row in results:
         errorstring = "<error "
         for key in self.KeyArray:
            errorstring += key + '="' + row[key] + '" '
         errorstring += '/>\n\n'

         descfileobj.write(errorstring)

      descfileobj.write("\n</results>\n");

      descfileobj.close( )
      

   def analyze(self, srcfilepath, level):
      filebuf = self.readfile(srcfilepath)

      results = self.analyzeBuffer(filebuf, level)

      self.outputFile(results, level + "_" + srcfilepath)

def helper(command):
   print """XMLFilter - A tool for xml filter

Syntax:
    %s [ -v | -h | files ]

Options:
    -h
    --help         Show this help text
    -v
    --version      Show the version
""" % (command)

if ( __name__ == "__main__"):
   argv = sys.argv
   argc = len(sys.argv)

   if argc != 2 or argv[1] == "-h" or argv[1] == "--help":
      helper(argv[0])
      sys.exit(0)

   if argv[1] == "-v" or argv[1] == "--version":
      print "XMLFilter version V0.0.1"
      sys.exit(0)

   filepath = argv[1]
   levels = ["Critical", "Serious", "Warning", "Information", "Style"]

   Handler = XMLHandler()
   # pdb.set_trace() 
   for level in levels :
      Handler.analyze(filepath, level)

   sys.exit(0)
