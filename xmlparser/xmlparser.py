#!/usr/bin/python
 
import xml.sax
import sys
import pdb
 
class XMLHandler(xml.sax.ContentHandler):
   def __init__(self, cond):
      self.Condition = cond
      self.RowArray = []
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
         "funcRetNull"              :"Warning",
         "memleak"                  :"Warning",
         "memleakOnRealloc"         :"Warning",
         "resourceLeak"             :"Warning",
         "deallocDealloc"           :"Warning",
         "deallocuse"               :"Warning",
         "mismatchAllocDealloc"     :"Warning",
         "mismatchSize"             :"Warning",
         "virtualDestructor"        :"Warning",
         "incrementboolean"         :"Warning",
         "moduloAlwaysTrueFalse"    :"Warning",
         "SizeofForNumericParameter":"Warning",
         "SizeofForArrayParameter"  :"Warning",
         "SizeofForPointerSize"     :"Warning",
         "sizeofsizeof"             :"Warning",
         "UnsignedDivision"         :"Warning",
         "NegativeBitwiseShift"     :"Warning",
         "autovar"                  :"Warning",
         "Danglingpointer"          :"Warning",
         "NestedLoop"               :"Warning",
         "unConditionalBreakinLoop" :"Warning",
         "IfCondition"              :"Warning",
         "strPlusChar"              :"Warning",
         "bitwiseOnBoolean"         :"Warning",
         "ComparisonOfBoolWithInt"  :"Warning",
         "ComparisonOfBoolWithBool" :"Warning",
         "ComparisonWithBool"       :"Warning",
         "assignIf"                 :"Warning",
         "oppositeInnerCondition"   :"Warning",
         "incorrectLogicOperator"   :"Warning",
         "clarifyCondition"         :"Warning",
         "StlMissingComparison"     :"Warning",
         "stlSortCheck"             :"Warning",
         "SwitchNoBreakUP"          :"Warning",
         "NoFirstCase"              :"Warning",
         "RecursiveFunc"            :"Warning",
         "UnintentionalOverflow"    :"Warning",
         "duplicateBranch"          :"Warning",
         "DuplicateExpression"      :"Warning",
         "selfAssignment"           :"Warning",
         "duplicateIf"              :"Warning",
         "STLFindError"             :"Warning",
         "unsafeFunctionUsage"      :"Warning",
         "uninitMemberVar"          :"Warning",

         # Information sub types
         "PreciseComparison"        :"Information",
         "Unsignedlessthanzero"     :"Information",
         "assignmentInAssert"       :"Information",
         "suspiciousSemicolon"      :"Information",
         "SuspiciousPriority"       :"Information",
         "FuncReturn"               :"Information",
         "BoolFuncReturn"           :"Information",
         "SwitchNoDefault"          :"Information",
         "SignedUnsignedMixed"      :"Information",
         "redundantCondition"       :"Information"
         }
 
   def startElement(self, tag, attrs):
      if tag == "error":
         # pdb.set_trace() 
         subtype = attrs["subid"]
         currule = self.RuleArray[subtype]
         if currule == self.Condition :
            row = {}
            for key in self.KeyArray:
               row[key] = attrs[key]
            # print "====row====:", row
            self.RowArray += [row]

   def outputFile(self, filepath="result.xml"):
      file_object = open(filepath, 'w')

      file_object.write('<?xml version="1.0" encoding="UTF-8"?>\n<results>\n\n');

      # pdb.set_trace() 
      for row in self.RowArray:
         errorstring = "<error "
         for key in self.KeyArray:
            errorstring += key + '="' + row[key] + '" '
         errorstring += '/>\n\n'

         file_object.write(errorstring)

      file_object.write("\n</results>\n");

      file_object.close( )
 
def helper(command):
   print """XMLFilter - A tool for xml filter

Syntax:
    %s {-v | -h | -f filter} [files]

Options:
    -f filter      Spicial filter condition
    -h
    --help         Show this help text
    -v
    --version      Show the version

Filter:
    Critical
    Serious
    Warning
    Information
    Style
""" % (command)

if ( __name__ == "__main__"):
   argv = sys.argv
   argc = len(sys.argv)

   # pdb.set_trace() 
   if argc == 2 and (argv[1] == "-v" or argv[1] == "--version"):
      print "XMLFilter version V0.0.1"
      sys.exit(0)
   elif argc == 2 and (argv[1] == "-h" or argv[1] == "--help"):
      helper(argv[0])
      sys.exit(0)
   elif argc != 4:
      print "input parameter error."
      helper(argv[0])
      sys.exit(1)

   fconf = argv[1]
   cond = argv[2]
   filepath = argv[3]
   if fconf != "-f":
      print "input parameter error."
      helper(argv[0])
      sys.exit(1)

   #  Critical, Serious, Warning, Information, Style
   if cond != "Critical" and cond != "Serious" and cond != "Warning" \
          and cond != "Information" and cond != "Style" :
      print "input filter parameter error."
      helper(argv[0])
      sys.exit(1)
   
   parser = xml.sax.make_parser()
   parser.setFeature(xml.sax.handler.feature_namespaces, 0)
 
   Handler = XMLHandler(cond)
   parser.setContentHandler(Handler)
   
   parser.parse(filepath)
   Handler.outputFile()

   sys.exit(0)
