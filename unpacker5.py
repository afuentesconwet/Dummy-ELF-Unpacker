from triton import ARCH, SYSCALL64
import pintool as Pintool

Triton = Pintool.getTritonContext()

writes = {}
calls = {}

def finicb():
	print("WRITES: ")
	print(writes)
	print("===================================================")
	print("CALLS: ")
	print(calls)
	print("===================================================")

# During a Call instruction, if we apply "getWrittenRegisters()",
# the rip (instruction pointer) will be one of the registers, and it
# will contain the next instruction to execute, which is the one to
# which the call jumps.

# Do the following to get destination addr of the call:
#  -> Triton.registers.getCurrentRegister(rip)

# If we obtain the RIP values BEFORE the execution of the Instruction,
# the destination address of the call will be different to the one appearing
# in the disassembly in those cases in which the address is direct and not calculated

# On the other hand, if we obtain the RIP values AFTER its execution, the RIP,
# will be pointing to the right address.

# Call es considerada una instruccion que hace Memory Writes, por que introduce
# en el stack la direccion a la que tiene que volver ret.
# Para solo quedarnos con las instrucciones que escriben en memoria codigo que no
# sean calls, debemos asegurarnos de que isMemoryWrite() y !isControlFlow()

#Los push tambien se consideran MemoryWrite por que se meten datos a la pila (parametros y vars locales)

# Usually there are much less call transfers than memory writes.

def instrbecb(instr):
	global writes
	#print(dir(instr))

	if instr.isMemoryWrite() and not instr.isControlFlow():
		#print("WRITE TO: ", instr.getStoreAccess())
		print("DISASM: ", instr.getDisassembly())
		#print(dir(instr))
		print("=======================================================")
		addr = instr.getStoreAccess()[0][0]
		if instr.getAddress() not in writes.keys():
			writes[hex(instr.getAddress())] = hex(addr.getAddress())

def instrafcb(instr):
	global calls
	if "call " in instr.getDisassembly():
		#print("DISASM: ", instr.getDisassembly())
		#print("DEST ADDR: ", hex(Pintool.getCurrentRegisterValue(Triton.registers.rip)))
		#print("==============================================================")
		instr_addr = instr.getAddress()
		if instr_addr not in calls.keys():
			calls[hex(instr_addr)] = hex(Pintool.getCurrentRegisterValue(Triton.registers.rip))

if __name__ == '__main__':
	aa = Triton.setArchitecture(ARCH.X86_64)

	# The unpacker does not use symbols,
	# it does not know about where "main" starts,
	# then we start from the entrypoint
	Pintool.startAnalysisFromEntry()
	#Pintool.startAnalysisFromSymbol('main')

	# The malware may not use Write and Red syscalls
	# then, we should keep track of all the instr that write
	# or read data to memory
	#Pintool.insertCall(syscallcb, Pintool.INSERT_POINT.SYSCALL_ENTRY)

	# Setup an Image Whitelist of qemu, to make
	# execution faster, way more faster.
	Pintool.insertCall(instrbecb, Pintool.INSERT_POINT.BEFORE)
	Pintool.insertCall(instrafcb, Pintool.INSERT_POINT.AFTER)
	Pintool.insertCall(finicb, Pintool.INSERT_POINT.FINI)

	Pintool.runProgram()
