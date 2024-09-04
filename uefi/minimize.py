#!/usr/bin/env python3
#
# @mebeim - 2024-07-20
#

import sys
from collections import namedtuple
from operator import attrgetter
from os import system
from pathlib import Path

from iced_x86 import Decoder, Instruction
from iced_x86.Mnemonic import ADD, SUB, PUSH, POP, RET


Chunk = namedtuple('Chunk', ['name', 'offset', 'size'])

InsnListT = list[Instruction]
ScheduleT = list[tuple[Chunk,InsnListT]]

ASM_DIR    = Path('asm')
ASM_SOURCE = Path('BGGP5_Asm_v3.asm')
EFI_BINARY = Path('BGGP5_Asm_v3.efi')

ENTRY_OFFSET = 0xe4
HEADER_CHUNKS = (
	Chunk('HOLE0', 0x0c, 12),
	Chunk('HOLE1', 0x1e, 14),
	Chunk('HOLE2', 0x44, 16),
	Chunk('HOLE3', 0x5c,  4),
	Chunk('HOLE4', 0x62, 38),
	Chunk('HOLE5', 0x8c, 32),
	Chunk('HOLE6', 0xbc,  8),
	Chunk('HOLE7', 0xd4, 16),
)


def jmp_size(ip: int, target: int) -> int:
	'''
	Calculate the size of a JMP instruction from instruction pointer ip to the
	given target address. The size is 2 bytes for short JMPs (if the offset
	between ip and target is small enough) and 5 bytes for long JMPs.
	'''
	if target > ip:
		off = target - ip - 2
	else:
		off = ip - target + 2

	return 2 if off < 0x80 else 5


def chunk_jmp_size(src: Chunk, dst: Chunk) -> int:
	'''
	Calculate the size of a JMP instruction from the end of the src chunk to
	the start of the dst chunk.
	'''
	return jmp_size(src.offset + src.size - 2, dst.offset)


def take_insns(insns: InsnListT, size: int) -> tuple[int,int]:
	'''
	Calculate and return the number of instructions that can fit in the given
	size, and the remaining size after taking those instructions.
	'''
	for n, insn in enumerate(insns):
		if size < len(insn):
			break
		size -= len(insn)
	else:
		n = len(insns)

	return n, size


def solve(insns: InsnListT, chunks: tuple[Chunk, ...], cur_chunk: Chunk,
		cost: int=0, min_cost: float=float('inf'), schedule: ScheduleT=[]) \
			-> tuple[ScheduleT,int]:
	'''
	Find an order for the given chunks and assign instructions to fill them such
	the amount of space wasted due to non-short JMPs and chunks not being
	completely filled with instructions is minimal.
	'''
	if not chunks:
		# Done, last chunks takes all remaining instructions
		return schedule + [(cur_chunk, insns)], cost

	best_schedule: ScheduleT|None = None

	# Try all possible next chunks (except last one, which needs to be last).
	# Consider last chunk IFF it's the only one left.
	n = len(chunks)
	n -= len(chunks) > 1

	for i in range(n):
		next_chunk = chunks[i]
		jmp_sz = chunk_jmp_size(cur_chunk, next_chunk)
		avail_size = cur_chunk.size - jmp_sz

		if avail_size < 0:
			# Can't even fit the final JMP here, not good
			continue

		split_idx, rem_sz = take_insns(insns, avail_size)

		# The cost is the amount of bytes wasted due to either a non-short JMP
		# or a chunk not being completely filled with insns. A perfect filling
		# of the chunk has 0 cost (jmp_sz == 2 and rem_sz == 0).
		new_cost = cost + jmp_sz - 2 + rem_sz
		if new_cost >= min_cost:
			continue

		cur_chunk_insns, rem_insns = insns[:split_idx], insns[split_idx:]
		new_schedule = schedule + [(cur_chunk, cur_chunk_insns)]
		rem_chunks = chunks[:i] + chunks[i + 1:]

		final_schedule, final_cost = solve(rem_insns, rem_chunks, next_chunk,
			new_cost, min_cost, new_schedule)

		if final_cost < min_cost:
			min_cost = final_cost
			best_schedule = final_schedule

		# Stop at the first optimal solution found. This corresponds to the case
		# where all chunks are completely filled with instructions and all the
		# JMPs are 2-byte short JMPs.
		if min_cost == 0:
			break

	return best_schedule, min_cost


def minimize(insns: InsnListT, chunks: tuple[Chunk,...], entry_offset: int) \
		-> tuple[int,tuple[Chunk,...],list[InsnListT]]:
	'''
	Find the best size for the ENTRY chunk and the best order for the subsequent
	chunks to minimize the amount of space wasted due to non-short JMPs and
	chunks not being completely filled with instructions.
	'''
	min_cost = float('inf')
	best_schedule: ScheduleT|None = None

	print(f'Need to schedule {len(insns)} instructions')
	print('Solving... ', end='', flush=True)

	# Try any possible sizes for the ENTRY chunk
	for entry_size in range(sum(map(len, insns))):
		entry_chunk = Chunk('ENTRY', entry_offset, entry_size)

		# Final (AHEAD) chunk will be after ENTRY and last in the schedule
		final_chunk = Chunk('AHEAD', entry_offset + entry_size, 0xffffffff)

		schedule, cost = solve(insns, chunks + (final_chunk,), entry_chunk)
		if cost < min_cost:
			min_cost = cost
			best_schedule = schedule

		# Stop at the first optimal solution found. This corresponds to the case
		# where all chunks are completely filled with instructions and all the
		# JMPs are 2-byte short JMPs.
		if cost == 0:
			break

	print('done!')
	assert best_schedule is not None
	return best_schedule


def main():
	src = (ASM_DIR / ASM_SOURCE)
	app = (ASM_DIR / EFI_BINARY)

	if not src.is_file():
		print(f'{src} not found!', file=sys.stderr)
		sys.exit('You are not launching this scipt from the right directory!')

	# Compile the binary
	if system(f'make -C {ASM_DIR} {EFI_BINARY}') != 0:
		sys.exit(f'Failed to compile {src}!')

	# Load the file and extract all the instructions. Code is assumed to start
	# at the ENTRY label and run linearly from there without JMPing around, i.e.
	# instructions are from ENTRY to the end of the file.
	data = app.read_bytes()
	insns = []

	for insn in Decoder(64, data[ENTRY_OFFSET:], ip=ENTRY_OFFSET):
		assert not insn.is_invalid
		insns.append(insn)

		# Stop at final RET
		if insn.mnemonic == RET:
			break

	print(f'Parsed {len(insns)} instructions')

	# We don't care about the prolog, skip initial PUSHs and SUB ESP,xxx.
	for i, insn in enumerate(insns):
		if insns[i].mnemonic not in (SUB, PUSH):
			break

	print(f'Ignoring prolog of {i} instructions')
	insns = insns[i:]

	# We don't care about the epilog, skip final ADD ESP,xxx, POPs and RET
	for i in range(len(insns) - 1, -1, -1):
		if insns[i].mnemonic not in (ADD, POP, RET):
			break

	print(f'Ignoring epilog of {len(insns) - (i + 1)} instructions')
	insns = insns[:i + 1]

	# Find optimal schedule
	schedule = minimize(insns, HEADER_CHUNKS, ENTRY_OFFSET)

	# Add dummy JMP insns for correct size calculation and insn display
	for i in range(len(schedule) - 1):
		jmp_sz = chunk_jmp_size(schedule[i][0], schedule[i + 1][0])
		schedule[i][1].append(next(Decoder(
			64, b'\xeb\xfe' if jmp_sz == 2 else b'\xe9\xfb\xff\xff\xff', ip=0)))

	# Start with just the heders
	file_sz = ENTRY_OFFSET

	# Add size of insns in ENTRY and last (AHEAD) chunk, which are after headers
	file_sz += sum(map(len, schedule[0][1]))
	file_sz += sum(map(len, schedule[-1][1]))

	# Add size of data constants to embed in the file
	data_sz  = len('https://binary.golf/5/5')
	data_sz += len('Host\0')
	data_sz += len('binary.golf\0')
	data_sz += 32 # 2 GUIDs
	file_sz += data_sz

	# Parts of the header that are not used as code
	pure_header_sz = ENTRY_OFFSET - sum(map(attrgetter('size'), HEADER_CHUNKS))

	print('-' * 40)
	print('Best possible file size:', file_sz, 'bytes')
	print('Of which pure header:', pure_header_sz, 'bytes')
	print('Of which data:', data_sz, 'bytes')
	print('\nExecution plan:')

	for chunk, insns in schedule[:-1]:
		used_sz = sum(map(len, insns))
		usz = f'{used_sz}/{chunk.size}'.rjust(5)

		if sys.stdout.isatty():
			usz = '\033[' + ('32' if used_sz == chunk.size else '1;31') + 'm' + usz + '\033[0m'

		print(f'    {chunk.name}: {len(insns):2d} insns, {usz} used bytes')

	chunk, insns = schedule[-1]
	used_sz = sum(map(len, insns))
	print(f'    {chunk.name}: {len(insns):2d} insns, {used_sz:2d} bytes')

	for chunk, insns in schedule:
		print(f'\n{chunk.name}:')

		for insn in insns:
			raw = data[insn.ip:insn.ip + len(insn)].hex()
			print(f'    {raw:16s}', insn)


if __name__ == '__main__':
	main()
