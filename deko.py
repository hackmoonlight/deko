import r2pipe
import sys
import sqlite3 as lite
from pdb import pm
import argparse
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.analysis.machine import Machine
from miasm2.expression.expression import ExprId, ExprInt32, ExprInt64, ExprAff, \
	 ExprMem
from miasm2.analysis.machine import Machine
from miasm2.core.bin_stream import bin_stream_str
from miasm2.ir.symbexec import symbexec
parser = argparse.ArgumentParser(description='DECOMPOSITION AND BINARY ANALYSIS')
parser.add_argument('-f', '--action',help='CHOSE THE ACTION TO EXECUTE , YOU CAN CHOSE:  [name] TO SHOW THE NAME OF FUNCTIONS, [addr] TO SHOW THE FUNCTION ADDRESS ,[size] TO SHOW FUNCTIONS SIZE [dump] TO HEXDUMP THE CONTENT OF EACH FUNCTION   ')
parser.add_argument( '-b','--binaryfile',help='ENTER THE BINARY FILE TO BEGIN ANALYSIS')
# parser.add_argument('-ex', '--export',help='')
parser.add_argument('-d', '--dump',help='HEXDUMP OF FUNCTION ')
parser.add_argument('-s', '--size',help='SIZE OF SPECIFIC FUNCTION ')
parser.add_argument('-a', '--address',help='ADDRESS OF SPECIFIC FUNCTION ')
parser.add_argument('-e', '--emulation',help='EMULATE THE SHELLCODE OF THE FUNCTION')
parser.add_argument('-o', '--emulationAtAddress',type= any ,help='CHOSE THE ADDRESS WHERE YOU WANT TO EMULATE ')
parser.add_argument('-se', '--symbexec',help='SYMBOLICALLY EXECUTE THE SHELLCODE OF THE FUNCTION')
argdAction = parser.parse_args()
argDump=parser.parse_args()
argSize=parser.parse_args()
argAdd=parser.parse_args()
argEmu=parser.parse_args()
argOffset=parser.parse_args()
argSymb=parser.parse_args()
argFile=parser.parse_args()
if argFile.binaryfile:
	print str(argFile.binaryfile)
 	r2 = r2pipe.open(str(argFile.binaryfile))
	r2.cmdj("aaa")
	function_list = r2.cmdj("aflj") # Analysis Function List Json

	i=0
	for function in function_list:
		if (argdAction.action=="addr") :
			 print("@ of  %s =  0x%x" %(function['name'],function['offset']))
		elif (argdAction.action=="size"):
			 print("[+] FunctionSize "+str(i)+": 0x%x " %(function['size']))
		elif(argdAction.action=="name"):
			print('[+] FunctionName' +str(i)+" " +function['name'])
		elif (argdAction.action=="dump"):
			print('[+] FunctionDump '+str(i)+":  "+function['name']+ " = " +(r2.cmd("p8" +" "+ str(function["size"])+ " @ " + function["name"]) ))
		i += 1
		try:
			con = lite.connect('deko.db')
			c = con.cursor()
			c.execute(" CREATE TABLE IF NOT EXISTS disas(NAME varchar(100) ,STADDR hex ,SIZE INTEGER, DUMP varchar(10000) )")
			sql = "INSERT INTO disas VALUES ('{name}','{addr}','{size}', '{dump}')".format(
				name=function['name'],
				addr=hex(function['offset']),
				size=hex(function["size"]),
				dump=r2.cmd("p8" +" "+ str(function["size"])+ " @ " + function["name"] ))
			c.execute(sql)
			con.commit()
		except lite.Error, e:
			if con:
				con.rollback()
				print "Error %s:" % e.args[0]
				sys.exit(1)
		finally:
			if con:
				c.close()
				con.close()
try:
	c = lite.connect('deko.db')
	cur = c.cursor()
	if argDump.dump :
		cur.execute("SELECT DUMP FROM disas where NAME='"+argDump.dump+"'")
		dataa = cur.fetchone()
		print "dump : %s" %(dataa)
	elif argSize.size:
		cur.execute("SELECT SIZE FROM disas where NAME='"+argSize.size+"'")
		dataa = cur.fetchone()
		print "size : %s" %(dataa)
	elif argAdd.address:
		cur.execute("SELECT STADDR FROM disas where NAME='"+argAdd.address+"'")
		dataa = cur.fetchone()
		print "address : %s" %(dataa)
	c.commit()
except lite.Error, e:
	if c:
		c.rollback()
		print "Error %s:" % e.args[0]
		sys.exit(1)
finally:
	if c:
		cur.close()
		c.close()
		
