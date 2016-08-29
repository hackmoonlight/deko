import r2pipe
import sys
import json
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
import unittest
import sys
import string
import random
from fcatalog_client.db_endpoint import TCPFrameClient,DBEndpoint
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
parser.add_argument('-sim', '--similarity',help='ip of the server ')
argdAction = parser.parse_args()
argDump=parser.parse_args()
argSize=parser.parse_args()
argAdd=parser.parse_args()
argEmu=parser.parse_args()
argOffset=parser.parse_args()
argSymb=parser.parse_args()
argFile=parser.parse_args()
argSimilarity=parser.parse_args()
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
if argEmu.emulation and argOffset.emulationAtAddress :
	try:
		c = lite.connect('deko.db')
		cur = c.cursor()
		cur.execute("SELECT DUMP FROM disas where NAME='"+argEmu.emulation+"'")
		dataa = cur.fetchone()
		data = dataa[0].decode("hex")
		print data
		# Init jitter
		myjit = Machine("x86_32").jitter(jit_type="gcc")
		myjit.init_stack()

		run_addr = argOffset.emulationAtAddress
		myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)
		myjit.jit.log_newbloc = True


		# Sentinelle called on terminate
		def code_sentinelle(jitter):
			jitter.run = False
			jitter.pc = 0
			return True
		myjit.push_uint32_t(0x1337beef)
		myjit.add_breakpoint(0x1337beef, code_sentinelle)
		myjit.init_run(run_addr)
		#myjit.continue_run()
		print myjit.cpu.dump_gpregs()
		eax = ExprId("RAX", 64)[:32]
		imm0, imm4, imm4_64 = ExprInt32(0), ExprInt32(4), ExprInt64(4)
		memdata = ExprMem(ExprInt32(run_addr), len(data) * 8)
	except lite.Error, e:
		if c:
			c.rollback()
			print "Error %s:" % e.args[0]
			sys.exit(1)
	finally:
		if c:
			cur.close()
			c.close()
if argSymb.symbexec:
	try:
		c = lite.connect('deko.db')
		cur = c.cursor()
		cur.execute("SELECT DUMP FROM disas where NAME='"+argSymb.symbexec+"'")
		dataa = cur.fetchone()
		# Create a bin_stream from a Python string
		bs = dataa[0].decode("hex")

		# Get a Miasm x86 32bit machine
		machine = Machine("x86_32")
		# Retrieve the disassemble and IR analysis
		dis_engine, ira = machine.dis_engine, machine.ira

		# link the disasm engine to the bin_stream
		mdis = dis_engine(bs)

		# Stop disassembler after the XOR
		mdis.dont_dis = [0x1C]
		# Disassemble one basic block
		block = mdis.dis_bloc(0)

		# instanciate an IR analysis
		ir_arch = ira(mdis.symbol_pool)
		# Translate asm basic block to an IR basic block
		ir_arch.add_bloc(block)

		# Store IR graph
		open('ir_graph.dot', 'w').write(ir_arch.graph.dot())

		# Initiate the symbolic execution engine
		# regs_init associates EAX to EAX_init and to on
		sb = symbexec(ir_arch, machine.mn.regs.regs_init)
		# sb.dump_id()
		# Start execution at address 0
		# IRDst represents the label of the next IR basic block to execute
		irdst = sb.emul_ir_blocs(ir_arch, 0,step=True)
		print 'ECX =', sb.symbols[machine.mn.regs.ECX]
		print 'ESP =', sb.symbols[machine.mn.regs.ESP]
		print 'EAX =', sb.symbols[machine.mn.regs.EAX]
	except lite.Error, e:
		if c:
			c.rollback()
			print "Error %s:" % e.args[0]
			sys.exit(1)
	finally:
		if c:
			cur.close()
			c.close()
if argFile.binaryfile and argSimilarity.similarity == "sim" :
	# Length of random part of db name:
	RAND_PART_LENGTH = 20

	# Amount of hashes used for the catalog1 signature.
	NUM_HASHES = 16

	# Address of remote server:
	remote = None

	def calculate_similarity():


		# suite = unittest.TestSuite()
		# Instantiate all tests and insert then into suite:
		tsuites = []
		for ts in functions_list:
			tsuites.append(\
					unittest.defaultTestLoader.loadTestsFromTestCase(ts)\
					)
		suite = unittest.TestSuite(tsuites)
		unittest.TextTestRunner().run(suite)


	def generat_name():
		"""
		Generate a random db name.
		"""
		rand_part = \
				''.join(random.choice(string.ascii_lowercase) for _ in \
				range(RAND_PART_LENGTH))

		return 'test_db_' + rand_part

	###########################################################################


	class Deko_db_test(unittest.TestCase):
		def test_basic_db_function(self):
			# Get a random db name:
			db_name = generat_name()
			frame_endpoint = TCPFrameClient(remote)
			dbe = DBEndpoint(frame_endpoint,db_name)
			try:
				c = lite.connect('deko.db')
				cur = c.cursor()
				cur.execute("SELECT * FROM disas")
				dataa = cur.fetchall()
				i=0
				for d in dataa :
					# print type(str(d[3]))
					dbe.add_function(str(d[0]),str(d[1]),str(d[3]))
					# dbe.add_function(d[0],d[1],d[3])
					dbe.request_similars(str(d[3]),2)
					# Check if the amount of returned functions is reasonable:
					similars = dbe.response_similars()
					print("+" + (150 * "-"))
					print ("|%s:"%d[0])
					print similars
					print("+" + (150 * "-"))
					i+=1
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
			dbe.close()


	functions_list = [Deko_db_test]

	############################################################################

	if __name__ == '__main__':
		address = "127.0.0.1"
		port = int(1337)

		# Set address of remote server:
		remote = (address,port)

		calculate_similarity()
