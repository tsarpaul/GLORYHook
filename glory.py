from os import path
import shutil
import struct
import argparse

import lief
from capstone import *
from keystone import *

md = None
ks = None
PLT_STUB_SIZE = 0x10
MEMORY_OPERAND = 2
INT_SZ = 8

PLT_INDEX_OFFSET = 0x6
PLT_JMP_OFFSET = 0xb

def isexec(segment):
	return segment.has(lief.ELF.SEGMENT_FLAGS.X) and segment.type == lief.ELF.SEGMENT_TYPES.LOAD

def isread(segment):
	return segment.has(lief.ELF.SEGMENT_FLAGS.R) and not segment.has(lief.ELF.SEGMENT_FLAGS.X) and segment.type == lief.ELF.SEGMENT_TYPES.LOAD

def pc_in_instr(i):
	return 'rip' in i.op_str or 'eip' in i.op_str

class Binary64():
	def _fix_got_after_injection(self, injected_offset, injected_size):
		with open(self.path, 'rb+') as f:
			# Fix header - it should point at its own VA
			f.seek(self.got_section.file_offset)
			got_header_va = self.got_section.virtual_address
			f.write(struct.pack("<Q", got_header_va))
		self.reload()

	def update_injection_metadata(self, injected_offset, injected_size, end_of_section=True, extend_backwards=False):
		def get_injected_section():
			if end_of_section:
				injected_section = self.binary.section_from_offset(injected_offset - 1)
			else:
				injected_section = self.binary.section_from_offset(injected_offset)
			return injected_section

		injected_section = get_injected_section()

		if extend_backwards:
			# TODO: Fix this if it is needed
			for i, s in enumerate(self.binary.sections):
				if s == injected_section:
					break

			last_section = self.binary.sections[i-1]
			self.binary.extend(last_section, injected_size)

			last_section.size -= injected_size
			injected_section.virtual_address -= injected_size
			injected_section.offset -= injected_size
			
			self.lief_write()
		else:
			# Extend section to prepare for injection
			self.binary.extend(injected_section, injected_size)
			self.lief_write()

			injected_section = get_injected_section()
			# Create a cavity for the injection by pushing code forward to fill the extension
			with open(self.path, 'rb+') as f:
				old_section_end = injected_section.file_offset + injected_section.size - injected_size
				bytes_to_move_sz = old_section_end - injected_offset
				f.seek(injected_offset)
				bytes_to_move = f.read(bytes_to_move_sz)
				f.seek(injected_offset + injected_size)
				f.write(bytes_to_move)

		self.reload()

	def apply_code_changes(self, code_changes):
		with open(self.path, 'rb+') as f:
			for cc in code_changes:
				f.seek(cc[0])
				f.write(bytearray(cc[1]))
		self.reload()

	def va(self, offset):
		section = self.binary.section_from_offset(offset)
		return section.virtual_address + offset - section.file_offset

	def update_injection_code(self, injected_offset, injected_size):
		def injection_in_positive_delta(injected_va, instruction_va, operand_delta):
			return operand_delta > 0 and instruction_va < injected_va < instruction_va + operand_delta
		
		def injection_in_negative_delta(injected_va, injected_size, instruction_va, operand_delta):
			return operand_delta < 0 and instruction_va > injected_va + injected_size and injected_va > instruction_va + operand_delta

		x_sections = []
		for s in self.binary.sections:
			if s.has(lief.ELF.SECTION_FLAGS.EXECINSTR):
				x_sections.append(s)

		code_changes = []
		for s in x_sections:
			code_start = s.file_offset
			code_va = s.virtual_address
			code_size = s.size

			# Fix relative addressings where the injection is located in the middle
			# Collect relative instructions
			with open(self.path, 'rb') as f:
				f.seek(code_start)
				injected_code = f.read(code_size)

			# Disassemble for the relatives
			injected_disassembly = md.disasm(injected_code, code_va)
			disassembly_index = 0
			disassembly_va = code_va

			for i in injected_disassembly:
				offset = code_start + disassembly_index
				#if offset == 0x3FED00:
				#	import pdb; pdb.set_trace()

				# Relative call
				if i.mnemonic in ['call', 'jmp'] and i.operands[0].type == MEMORY_OPERAND:
					# Capstone resolves imm to the appropriate address, instead of a delta
					imm = i.operands[0].imm
					new_imm = None

					if self.va(offset) > self.va(injected_offset) + injected_size > imm:
						new_imm = imm - injected_size
					elif self.va(offset) < self.va(injected_offset) < imm:
						new_imm = imm + injected_size

					if new_imm is not None:
						# Keystone does not resolve imm to appropriate address, so we have to recalculate the offset
						new_imm = new_imm - disassembly_va 
						new_asm_str = f'{i.mnemonic} {hex(new_imm)};'
						new_asm, count = ks.asm(new_asm_str)
						assert(len(new_asm) == i.size)  # TODO: If this happens we overflowed, we'll need to inject extra code to add up the relative call
						code_changes.append((offset, new_asm))

				elif pc_in_instr(i):
					rip_operand_index = 0
					try:
						if i.operands[1].mem.disp != 0:
							rip_operand_index = 1
					except IndexError:
						pass

					disp = i.operands[rip_operand_index].mem.disp
					new_disp = None

					if(injection_in_positive_delta(self.va(injected_offset), self.va(offset), disp + i.size)):
						new_disp = disp + injected_size
					elif(injection_in_negative_delta(self.va(injected_offset), injected_size, self.va(offset), disp + i.size)):
						new_disp = disp - injected_size

					if new_disp is not None:
						new_asm_str = f'{i.mnemonic} {i.op_str};'
						new_asm_str = new_asm_str.replace(str(hex(disp)), hex(new_disp))
						new_asm, count = ks.asm(new_asm_str)
						assert(len(new_asm) == i.size)
						code_changes.append((offset, new_asm))

				disassembly_index += i.size
				disassembly_va += i.size

		self.apply_code_changes(code_changes)


	def __init__(self, path):
		self.path = path
		self.reload()

		self.arch = self.binary.header.machine_type
		if self.arch not in [lief.ELF.ARCH.x86_64, lief.ELF.ARCH.i386]:
			raise("Unsupported architectures!")

		exec_segs = [seg for seg in self.binary.segments if isexec(seg)]
		read_segs = [seg for seg in self.binary.segments if isread(seg)]
		assert(len(exec_segs) == 1)
		assert(len(read_segs) == 1)

	def lief_write(self):
		self.binary.write(self.path)
		self.reload()

	def reload(self):
		"""Using old LIEF primitives MAY RESULT IN UNDEFINED BEHAVIOR after reloading!"""
		self.binary = lief.parse(self.path)
		self.plt_section = self.binary.get_section('.plt')
		self.text_section = self.binary.get_section('.text')
		self.got_section = self.binary.get_section('.got')
		self.load_segs = [seg for seg in self.binary.segments if seg.type == lief.ELF.SEGMENT_TYPES.LOAD]
		self.exec_seg = self.load_segs[0]
		self.read_seg = self.load_segs[1]

	def inject(self, content, offset, end_of_section=True, extend_backwards=False):
		size = len(content)

		# Adjust the binary before injecting
		self.update_injection_metadata(offset, size, end_of_section, extend_backwards)

		with open(self.path, 'rb+') as f:
			f.seek(offset)
			f.write(content)
		self.reload()

		self.update_injection_code(offset, size)

	def fix_new_plt_entries(self, injection_start, injection_size, got_start, got_sz):
		# Minus header and adjust to index 0
		max_got_index = got_sz//0x8 - 1 - 3
		#max_got_index = (self.plt_section.size-injection_size)//0x10 - 1
		injection_end = injection_start + injection_size

		got_end = got_start + got_sz
		got_end_va = self.va(got_end)

		code_changes = []
		# Fix our new PLT entries
		for i, plt_entry in enumerate(range(injection_start, injection_end, 0x10)):
			delta_from_plt_start = plt_entry - self.plt_section.file_offset
			plt_entry_va = self.plt_section.virtual_address + delta_from_plt_start
			got_entry = got_end + i*INT_SZ
			got_entry_va = got_end_va + i*INT_SZ

			# Fix GOT entry, should hold (PLT_entry + 0x6) initially
			plt_entry_stub_va = plt_entry_va + 0x6
			code_changes.append((got_entry, struct.pack("<Q", plt_entry_stub_va)))

			# Fix jmp to GOT
			got_jmp_delta = got_entry_va - plt_entry_va - 6  # minus instruction size
			asm, count = ks.asm(f"jmp [rip+{got_jmp_delta}]")
			code_changes.append((plt_entry, asm))

			# Fix GOT index in PLT stub
			plt_index_offset = plt_entry + PLT_INDEX_OFFSET
			max_got_index += 1
			asm, count = ks.asm(f"push {max_got_index}; nop; nop; nop")
			assert(len(asm) == 5)
			code_changes.append((plt_index_offset, asm))

			# Fix jmp to PLT stub
			plt_jmp_offset = plt_entry_va + PLT_JMP_OFFSET
			jmp_delta = self.plt_section.offset - plt_jmp_offset
			asm, count = ks.asm(f"jmp {jmp_delta};")
			code_changes.append((plt_jmp_offset, asm))

		self.apply_code_changes(code_changes)

	def merge_plt(self, plt_code, binary):
		plt_end_offset = self.plt_section.offset + self.plt_section.size
		print("[+] Injecting new PLT")
		self.inject(plt_code, plt_end_offset)
		
		print("[+] Extending GOT for new PLT")
		got_start = self.got_section.file_offset
		got_sz = self.got_section.size
		got_end = got_start + got_sz

		new_entries_count = len(plt_code)//0x10
		extension_sz = new_entries_count * INT_SZ
		extension_sz = (extension_sz//0x20)*0x20+0x20  # Align to 0x10
		self.inject(b'\x00' * extension_sz, got_end)

		print("[+] Fixing injected PLT")
		self.fix_new_plt_entries(plt_end_offset, len(plt_code), got_start, got_sz)

		self._fix_got_after_injection(plt_end_offset, len(plt_code))

		print("[+] Injecting PLT relocations")
		self.inject_dynamic_relocations(binary, got_end)

	def inject_dynamic_relocations(self, binary, got_end):
		got_entry = self.va(got_end)
		for rel in binary.binary.pltgot_relocations:
			rel.address = got_entry
			got_entry += 8
			self.binary.add_pltgot_relocation(rel)
		self.lief_write()

	def merge_symbols(self, binary):
		# TODO: Remove this?
		auxiliary_map = {}
		for symver in self.binary.symbols_version:
			if symver.has_auxiliary_version:
				auxiliary_map[symver.symbol_version_auxiliary.name] = symver.value

		# Skip first null symbol
		symbols = list(binary.binary.dynamic_symbols)[1:]
		for sym in symbols:
			self.binary.add_dynamic_symbol(sym)

		self.lief_write()

	def get_imports(self):
		"""Map PLT calls"""
		imports = {}
		dynamic_symbols = {s.value: s.name for s in self.binary.dynamic_symbols if s.type == lief.ELF.SYMBOL_TYPES.FUNC}

		# To be more precise, we should read the initial value in the GOT entry.
		# The relocation index will match the PLT index in an untampered binary so this implementation should be fine
		for i, r in enumerate(self.binary.pltgot_relocations):
			plt_address = self.plt_section.virtual_address + 0x10 + i * 0x10
			imports[plt_address] = r.symbol.name

		return imports

	def get_import_callers(self):
		calls = []

		imports = self.get_imports()

		# Disassemble text section to find calls to imports(PLT)
		text_start = self.text_section.file_offset
		text_va = self.text_section.virtual_address
		text_size = self.text_section.size

		with open(self.path, 'rb') as f:
			f.seek(text_start)
			code = f.read(text_size)

		disas = md.disasm(code, text_va)
		disassembly_index = 0
		disassembly_va = text_va

		# Look for calls into PLT
		for i in disas:
			offset = text_start + disassembly_index

			if i.mnemonic == 'call' and i.operands[0].type == MEMORY_OPERAND:
				# Capstone resolves imm to the appropriate address, instead of a delta
				imm = i.operands[0].imm

				if self.plt_section.virtual_address <= imm < (self.plt_section.virtual_address + self.plt_section.size):
					calls.append([i, offset, imports[imm]])

			disassembly_index += i.size

		return calls

	def replace_named_calls(self, start, end, calls, new_call_map):
		code_changes = []

		for call in calls:
			instr, offset, name = call[0], call[1], call[2]
			if name not in new_call_map:
				continue
			
			# Calculate new jump to the overriding function
			new_dest = new_call_map[name]
			new_imm = new_dest - offset
			asm, count = ks.asm(f'call {new_imm}')
			assert(len(asm) == instr.size)
			code_changes.append((offset, asm))

		self.apply_code_changes(code_changes)

	def get_hook_exports(self):
		exports = {}
		for e in self.binary.exported_functions:
			if e.name.startswith('gloryhook_'):
				new_name = e.name.replace('gloryhook_', '')
				exports[e.address] = new_name
		return exports

	def merge_binary_code(self, binary):
		# Add the new binary's code and read
		new_code = bytes(binary.exec_seg.content)
		merged_code_base_addr = self.exec_seg.file_offset + self.exec_seg.physical_size

		self.inject(new_code, merged_code_base_addr)
		self.lief_write()

		# TODO: Fix code to work with read segment too
		read_seg_end = self.read_seg.file_offset + self.read_seg.physical_size
		self.inject(bytes(binary.read_seg.content), read_seg_end)
		self.lief_write()

		# Fix new code imports
		new_import_callers = binary.get_import_callers()
		for nic in new_import_callers:
			# Adjust address for new binary
			nic[1] += merged_code_base_addr

		imports = self.get_imports()  # Collect name->PLT addresses
		imports = {v:k for (k, v) in imports.items()}  # Flip addr:name to name:addr
		self.replace_named_calls(merged_code_base_addr, merged_code_base_addr + len(new_code), new_import_callers, imports)

		# Replace PLT callers with functions from new binary
		import_callers = self.get_import_callers()
		exports = binary.get_hook_exports()
		exports = {v:k for (k, v) in exports.items()}  # Flip addr:name to name:addr
		for name, addr in exports.items():
			# Adjust address for new binary
			exports[name] += merged_code_base_addr

		self.replace_named_calls(self.text_section.file_offset, self.text_section.file_offset + self.text_section.size, import_callers, exports)

class Merger:
	# TODO: Add support for multiple executable LOAD segments
	def __init__(self, paths, out_path):
		self.binaries = [Binary64(p) for p in paths]
		
		arch = self.binaries[0].arch
		if not all([binary.arch == arch for binary in self.binaries]):
			raise("Inconsistent arch in binaries!")

		# Setup the new merged file
		shutil.copy(self.binaries[0].path, out_path)
		self.new_binary = Binary64(out_path)

	def merge(self):
		# Merge loadable segments
		for binary in self.binaries[1:]:
			try:
				binary.binary.get_section('.got.plt')
			except:
				pass
			else:
				print("[!] Currently we do not support injecting binaries with .got.plt. Recompile it with -zrelro -znow")
				exit(1)

			offset = binary.plt_section.offset + PLT_STUB_SIZE  # Skip PLT stub
			size = binary.plt_section.size - PLT_STUB_SIZE
			with open(binary.path, 'rb') as f:
				f.seek(offset)
				plt_code = f.read(size)

			self.new_binary.merge_symbols(binary)	
			self.new_binary.merge_plt(plt_code, binary)
			self.new_binary.merge_binary_code(binary)

		print('[+] Done!')

if __name__ == "__main__":
	# TODO: Add a check that we're on a good LIEF release
	# TODO: Add support for more than 2 binaries(?)

	parser = argparse.ArgumentParser(description='GLORYHook')
	parser.add_argument('file1', help='path to file to install hooks on')
	parser.add_argument('file2', help='file with gloryhooks')
	parser.add_argument('-o', '--output', help='output path', required=True)

	args = parser.parse_args()

	path1 = args.file1
	path2 = args.file2
	out_path = args.output

	if not (path.exists(path1) and path.exists(path2)):
		print("[!] ERR: One of the supplied input paths does not exist!")
		exit(1)

	print('[+] Beginning merge!')
	merger = Merger([path1, path2], out_path)
	md_arch = CS_MODE_64 if merger.binaries[0].arch == lief.ELF.ARCH.x86_64 else CS_MODE_32
	ks_arch = KS_MODE_64 if md_arch == CS_MODE_64 else KS_MODE_32
	md = Cs(CS_ARCH_X86, md_arch) 
	ks = Ks(KS_ARCH_X86, ks_arch)
	md.detail = True
	merger.merge()
	
