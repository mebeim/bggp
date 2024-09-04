#!/usr/bin/env python3
#
# @mebeim - 2024-07-10
#
# Run EDKII OVMF in qemu-system-x86_64 and drop into the UEFI shell.
# See ./run.py --help for usage information.
#

import atexit
import socket
import sys
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from os import getenv
from pathlib import Path
from shutil import rmtree
from string import ascii_lowercase, digits
from subprocess import Popen
from tempfile import mkdtemp
from textwrap import TextWrapper
from time import sleep
from typing import Tuple, Optional, Iterable


# Dir for temporary files created on demand that will be wiped on exit / CTRL+C
TMPDIR = None
# How much time to wait before starting to send keystrokes in auto mode
EFI_SHELL_WAIT_TIME = 25


def get_tmpdir():
	global TMPDIR

	if TMPDIR is None:
		TMPDIR = Path(mkdtemp(prefix='bggp5-qemu-run-'))
		atexit.register(rmtree, TMPDIR)

	return TMPDIR


def log(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)


def wrap_help(body: str, width: int=65) -> str:
	tx = TextWrapper(width, break_long_words=False, replace_whitespace=False)
	return '\n'.join(tx.fill(line) for line in body.splitlines() if line.strip())


def parse_args() -> Namespace:
	ap = ArgumentParser(
		description=wrap_help('Run EDKII OVMF in qemu-system-x86_64 and '
			'optionally also automatically run some UEFI apps through UEFI '
			'shell with QEMU monitor -- (C) 2024 Marco Bonelli (@mebeim)', 69),
		formatter_class=RawTextHelpFormatter
	)

	ap.add_argument('apps', metavar='path/to/APP.efi', nargs='*',
		help=wrap_help('when --auto or --auto-verify are used, copy these UEFI '
			'apps into build/ and automatically run them after starting QEMU'))
	ap.add_argument('--auto', action='store_true',
		help=wrap_help('automatically run the UEFI apps (sends shell input '
			'through QEMU monitor)'))
	ap.add_argument('--auto-verify', action='store_true',
		help=wrap_help('Like --auto, but also redirect serial to a temporary '
			'file and verify that one successful BGGP5 download per UEFI app '
			'is logged (you will not see any output)'))
	ap.add_argument('--edk2-debug', action='store_true',
		help=wrap_help('enable EDK II debug output to ./edk2-debug.log (only '
			'useful if you are running an EDK II debug build)'))
	ap.add_argument('--kvm', action='store_true',
		help=wrap_help('enable KVM for faster emulation'))

	return ap.parse_args()


def qemu_run(ovmf_code: Path, ovmf_vars: Path, fs_dir: Path,
		serial_log: Optional[Path]=None, monitor: bool=False, kvm: bool=False,
		edk2_debug: bool=False) -> Tuple[Popen,Optional[socket.socket]]:
	argv = [
		'qemu-system-x86_64',
		'-machine', 'q35',
		'-m', '2G',
		'-cpu', 'max',
		'-nographic',
		'-no-reboot',
		'-drive', f'if=pflash,format=raw,unit=0,file={ovmf_code},readonly=on',
		'-drive', f'if=pflash,format=raw,unit=1,file={ovmf_vars}',
		'-drive', f'format=raw,file=fat:rw:{fs_dir}',
		'-global', 'driver=cfi.pflash01,property=secure,value=on',
		'-nic', 'user,model=virtio-net-pci'
	]

	if serial_log:
		argv += ['-serial', f'file:{serial_log}']
	else:
		argv += ['-serial', 'stdio']

	if monitor:
		# Create a FIFO pipe for QEMU monitor interface in a temporary dir
		monitor_sock_path = get_tmpdir() / 'monitor.fifo'
		argv += ['-monitor', f'unix:{monitor_sock_path},server,nowait']
	else:
		argv += ['-monitor', 'none']

	if kvm:
		argv += ['-enable-kvm']
	if edk2_debug:
		argv += [
			'-global', 'isa-debugcon.iobase=0x402',
			'-debugcon', 'file:./edk2-debug.log'
		]

	qemu = Popen(argv)

	if monitor:
		monitor_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

		# Wait for monitor UNIX socket to be created by QEMU and connect to it
		while 1:
			try:
				monitor_sock.connect(str(monitor_sock_path))
				break
			except FileNotFoundError:
				sleep(0.1)
	else:
		monitor_sock = None

	return qemu, monitor_sock


def qemu_send_as_keys(monitor: socket.socket, keys: str):
	keymap = {c: c for c in ascii_lowercase + digits}
	keymap |= {c.upper(): f'shift-{c}' for c in ascii_lowercase}
	keymap |= {
		'(': 'shift-9', ')': 'shift-0', '.': 'dot', ' ': 'spc',
		"'": 'apostrophe', '"': 'shift-apostrophe',
		'=': 'equal', '+': 'shift-equal', '-': 'minus', '_': 'shift-minus',
		',': 'comma', ';': 'semicolon', '&': 'shift-7', '\n': 'ret'
	}

	for k in keys:
		monitor.sendall(f'sendkey {keymap[k]}\n'.encode())

	# Just for good measure...
	sleep(0.5)


def run_apps(qemu_monitor: socket.socket, apps: Iterable[Path], verbose: bool=False):
	if verbose:
		log('Waiting for UEFI shell + DHCP lease...')

	if getenv('DEV') == '1':
		# Do things faster while devving on my system
		sleep(3)
		# Skip iPXE wait
		qemu_send_as_keys(qemu_monitor, '\n')
		# Skip shell wait
		qemu_send_as_keys(qemu_monitor, '\n')
		# Wait for commands and DHCP
		sleep(5)
	else:
		# Wait for iPXE timeout + UEFI shell timeout + commands + DHCP
		sleep(EFI_SHELL_WAIT_TIME)

	qemu_send_as_keys(qemu_monitor, 'ifconfig -l\n')

	for app in apps:
		if verbose:
			log(f'Running {app.name}...')

		qemu_send_as_keys(qemu_monitor, f'{app.stem}\n')
		sleep(2)

	qemu_monitor.sendall(b'quit\n')


def main():
	args = parse_args()
	rootfs = Path('build')

	if not rootfs.is_dir():
		log(f'ERROR: ./{rootfs} directory not found!')
		log('Did you build EDK II first?')
		log('Are you rinning this script from the directory where it is located?')
		sys.exit(1)

	if args.auto_verify:
		args.auto = True

	if args.auto:
		if not args.apps:
			log('ERROR: --auto and --auto-verify require at least one APP argument!')
			sys.exit(1)

		apps = list(map(Path, args.apps))

		if not apps:
			log('No apps to run!')
			sys.exit(1)

		# Copy apps into build/ directory if they are outside
		for a in apps:
			if not a.is_file():
				log(f'ERROR: {a} not found or not a file!')
				sys.exit(1)

			if a.parent != rootfs:
				(rootfs / a.name).write_bytes(a.read_bytes())

	ovmf_code      = rootfs / 'OVMF_CODE.fd'
	ovmf_vars      = rootfs / 'OVMF_VARS.fd'
	tmp_ovmf_vars  = get_tmpdir() / 'OVMF_VARS.copy.fd'
	startup_script = Path('startup.nsh')

	# Check that we have all the necessary files
	for f in (ovmf_code, ovmf_vars, startup_script):
		if not f.is_file():
			log(f'ERROR: {f} not found or not a file!')
			sys.exit(1)

	# Copy the startup script in the fs
	Path(rootfs / 'startup.nsh').write_bytes(startup_script.read_bytes())
	# Create a copy of the OVMF_VARS.fd file since it will be mounted R/W
	tmp_ovmf_vars.write_bytes(ovmf_vars.read_bytes())

	# Print some info for the user of this script to understand what's going on
	if args.auto:
		n_apps = len(apps)
		print(f'Will wait {EFI_SHELL_WAIT_TIME}s for UEFI shell + DHCP lease, '
			f'then run {n_apps} app{"s"[:n_apps ^ 1]}:\n', file=sys.stderr)

		for a in apps:
			log(f'  - {a.name} ({a.stat().st_size} bytes)')
		log('')

		if getenv('DEV') != '1':
			# Give some time to read the above before the VM clears the terminal
			if not args.auto_verify:
				for i in range(5, 0, -1):
					print(f'\rLaunching QEMU in {i}s...', file=sys.stderr, end='', flush=True)
					sleep(1)
	else:
		log('Launching QEMU...')

	if args.auto_verify:
		serial_log = get_tmpdir() / Path('serial.log')
	else:
		serial_log = None

	qemu, monitor_sock = qemu_run(ovmf_code, tmp_ovmf_vars, rootfs, serial_log,
		args.auto, args.kvm, args.edk2_debug)

	if args.auto:
		run_apps(monitor_sock, apps, args.auto_verify)

	try:
		qemu.wait()
	except KeyboardInterrupt:
		pass

	if args.auto_verify:
		data = b'Another #BGGP5 download!! @binarygolf https://binary.golf\n'

		with serial_log.open('rb') as f:
			serial_output = f.read()

		n_ok = serial_output.count(data)
		log(f'{n_ok}/{n_apps} successful BGGP5 downloads')
		sys.exit(int(n_ok != n_apps))


if __name__ == '__main__':
	main()
