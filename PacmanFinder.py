# Return all branches that lead to gadgets within a given function
# @category pacman
# @author Joseph Ravichandran

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.util import SymbolicPropogator

# How many instructions deep should we scan?
SIMULATED_ROB_DEPTH=32

# Instructions that authenticate a PAC'd pointer
PAC_INSN_NAMES = [
	'aut',
]

# Instructions that are instant gadgets (auth and use)
# Comment out any of these to ignore them (eg. to ignore BLRAA's)
# Recall BLRAA will speculatively load incorrect PACs roughly 50% of the time due to a
# race condition between the auth and load. Refer to the DEF CON 30 PACMAN talk for more info.
PAC_AUTH_AND_USE_GADGET_NAMES = [
	# 'retaa',
	# 'retab',
	'blraa',
	'blrab',
	'blraaz',
	'blrabz',
]

# Collect metrics on the gadgets we found
# average distance = TOTAL_DISTANCE / TOTAL_GADGETS
TOTAL_GADGETS=0
TOTAL_DISTANCE=0
TOTAL_DATA_GADGETS=0
TOTAL_INSN_GADGETS=0

# Should we write to the output file?
SHOULD_WRITE=True

# Should we only limit the exploration to defined BSD syscalls? (AKA symbols returned by get_all_syscalls)
LIMIT_TO_SYSCALLS=False

# Where do we write our logs?
OUTPUT_PATH="/tmp/setme"

# Report all gadgets in the symbol `fn_in` (writing outputs to the file `file_to_write`)
def find_gadgets_in(fn_in, file_to_write):
	global TOTAL_GADGETS, TOTAL_DISTANCE, SHOULD_WRITE, TOTAL_DATA_GADGETS, TOTAL_INSN_GADGETS

	target = fn_in
	startAddress = target.getBody().getMinAddress()
	endAddress = target.getBody().getMaxAddress()

	cond_branches = []
	search_addrs = []
	cur_inst = getInstructionAt(startAddress)
	while(cur_inst is not None and getFunctionContaining(cur_inst.getAddress()) == target):
		addr = cur_inst.getAddress()

		flows = cur_inst.getFlows()
		if len(flows) != 0:
			inst_name = cur_inst.getMnemonicString()

			if inst_name != 'b' and inst_name != 'bl' and inst_name not in PAC_INSN_NAMES and inst_name not in PAC_AUTH_AND_USE_GADGET_NAMES:
				search_addrs.append(getInstructionAfter(cur_inst).getAddress())
				search_addrs.append(flows[0])
				cond_branches.append(cur_inst)

		cur_inst = getInstructionAfter(cur_inst)

	gadgets_found = []
	for search_start in search_addrs:
		cur_inst = getInstructionAt(search_start)

		# Track all addresses that are the result of PAC ops- these are inserted into
		# registers which we consider tained
		# TODO: Use the SymbolicPropogation engine here instead
		speculative_taint = []
		taint_kinds=[]

		for i in range(SIMULATED_ROB_DEPTH):
			if cur_inst is None:
				break

			inst_name = cur_inst.getMnemonicString()
			if len(cur_inst.getFlows()) != 0 and inst_name not in PAC_INSN_NAMES and inst_name not in PAC_AUTH_AND_USE_GADGET_NAMES:
				# Found a second branch- stopping here
				break

			if 'ld' in inst_name:
				for input_reg in cur_inst.getInputObjects():
					is_reg = str(input_reg)[0] == 'x'

					if is_reg:
						if str(input_reg) in speculative_taint:
							TOTAL_DISTANCE+=i

							gadget_kind = '?'
							if 'i' in taint_kinds:
								TOTAL_INSN_GADGETS += 1
								gadget_kind = 'i'
							if 'd' in taint_kinds:
								TOTAL_DATA_GADGETS += 1
								gadget_kind = 'd'
							if 'i' in taint_kinds and 'd' in taint_kinds:
								gadget_kind='x'
								# Something funky is going on
								print(taint_kinds)
								print("DOUBLE TROUBLE")
							gadgets_found.append((gadget_kind, search_start))

			# No need to even do taint tracking, these instructions are instant gadgets
			# They also leave the function so we leave with them
			for instant_gadget_name in PAC_AUTH_AND_USE_GADGET_NAMES:
				if inst_name[0:len(instant_gadget_name)] == instant_gadget_name:
					TOTAL_DISTANCE += i
					gadgets_found.append(('i', search_start))
					TOTAL_INSN_GADGETS += 1
					break

			for pac_name in PAC_INSN_NAMES:
				if inst_name[0:len(pac_name)] == pac_name:
					# Got PAC instruction: cur_inst, cur_inst.getInputObjects(), cur_inst.getPcode()
					for result in cur_inst.getResultObjects():
						if 'd' in inst_name:
							taint_kinds.append('d')
							taint_kinds.append(inst_name)
						if 'i' in inst_name:
							taint_kinds.append('i')
							taint_kinds.append(inst_name)
						speculative_taint.append(result)

					if 'sp' in inst_name:
						speculative_taint.append('sp')
						if 'd' in inst_name:
							taint_kinds.append('d')
							taint_kinds.append(inst_name)
						if 'i' in inst_name:
							taint_kinds.append('i')
							taint_kinds.append(inst_name)
					else:
						result = str(cur_inst).split(',')[0].split(" ")[1]
						speculative_taint.append(result)
						if 'd' in inst_name:
							taint_kinds.append('d')
							taint_kinds.append(inst_name)
						if 'i' in inst_name:
							taint_kinds.append('i')
							taint_kinds.append(inst_name)

			if 'ret' in inst_name and inst_name not in PAC_AUTH_AND_USE_GADGET_NAMES:
				# Found a return- stop analysis here
				break

			cur_inst = getInstructionAfter(cur_inst)

	if len(gadgets_found) != 0:
		if SHOULD_WRITE:
			file_to_write.write("I found " + str(len(gadgets_found)) + " gadgets in " + str(fn_in) + " at " + str(gadgets_found) + "\n")
		TOTAL_GADGETS += len(gadgets_found)

def main():
	global LIMIT_TO_SYSCALLS, OUTPUT_PATH
	all_syscalls = get_all_syscalls()

	if OUTPUT_PATH == "/tmp/setme":
		print("You need to set the output path!")
		return

	with open(OUTPUT_PATH, "w") as file_w:
		if LIMIT_TO_SYSCALLS == False:
			# Look at everything
			for fn in currentProgram.getFunctionManager().getFunctions(True):
				find_gadgets_in(fn, file_w)

		if LIMIT_TO_SYSCALLS == True:
			for item in all_syscalls:
				potentialTargets = getGlobalFunctions("_" + item)
				if len(potentialTargets) == 0:
					print("The target method wasn't found")
					continue
				elif len(potentialTargets) > 1:
					print("Multiple targets found! Picking just one")
				target = potentialTargets[0]
				find_gadgets_in(target, file_w)

	print("In total there are", TOTAL_GADGETS, "gadgets in this program")
	print("On average there are", float(TOTAL_DISTANCE) / float(TOTAL_GADGETS), "instructions between a branch and the resulting gadget in this program")
	print("There are", TOTAL_INSN_GADGETS, "instruction gadgets")
	print("There are", TOTAL_DATA_GADGETS, "data gadgets")

# Returns a list of all BSD system calls for exploration
# You can put whatever symbols you want here and if LIMIT_TO_SYSCALLS is set, the analysis will be limited to just those
def get_all_syscalls():
	return set(["nosys",
		"exit",
		"fork",
		"read",
		"write",
		"open",
		"sys_close",
		"wait4",
		"enosys",
		"link",
		"unlink",
		"enosys",
		"chdir",
		"fchdir",
		"mknod",
		"chmod",
		"chown",
		"enosys",
		"getfsstat",
		"enosys",
		"getpid",
		"enosys",
		"enosys",
		"setuid",
		"getuid",
		"geteuid",
		"ptrace",
		"recvmsg",
		"sendmsg",
		"recvfrom",
		"accept",
		"getpeername",
		"getsockname",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"access",
		"chflags",
		"fchflags",
		"sync",
		"kill",
		"nosys",
		"getppid",
		"nosys",
		"sys_dup",
		"pipe",
		"getegid",
		"nosys",
		"nosys",
		"sigaction",
		"getgid",
		"sigprocmask",
		"getlogin",
		"setlogin",
		"acct",
		"sigpending",
		"sigaltstack",
		"ioctl",
		"reboot",
		"revoke",
		"symlink",
		"readlink",
		"execve",
		"umask",
		"chroot",
		"nosys",
		"nosys",
		"nosys",
		"msync",
		"vfork",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"munmap",
		"mprotect",
		"madvise",
		"nosys",
		"nosys",
		"mincore",
		"getgroups",
		"setgroups",
		"getpgrp",
		"setpgid",
		"setitimer",
		"nosys",
		"swapon",
		"getitimer",
		"nosys",
		"nosys",
		"sys_getdtablesize",
		"sys_dup2",
		"nosys",
		"sys_fcntl",
		"select",
		"nosys",
		"fsync",
		"setpriority",
		"socket",
		"connect",
		"nosys",
		"nosys",
		"nosys",
		"getpriority",
		"nosys",
		"nosys",
		"nosys",
		"bind",
		"setsockopt",
		"listen",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"sigsuspend",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"gettimeofday",
		"getrusage",
		"getsockopt",
		"nosys",
		"nosys",
		"readv",
		"writev",
		"settimeofday",
		"fchown",
		"fchmod",
		"nosys",
		"setreuid",
		"setregid",
		"rename",
		"nosys",
		"nosys",
		"sys_flock",
		"mkfifo",
		"sendto",
		"shutdown",
		"socketpair",
		"nosys",
		"nosys",
		"nosys",
		"mkdir",
		"rmdir",
		"utimes",
		"futimes",
		"adjtime",
		"nosys",
		"gethostuuid",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"setsid",
		"nosys",
		"nosys",
		"nosys",
		"getpgid",
		"setprivexec",
		"pread",
		"pwrite",
		"nfssvc",
		"nosys",
		"statfs",
		"fstatfs",
		"unmount",
		"nosys",
		"getfh",
		"nosys",
		"nosys",
		"nosys",
		"quotactl",
		"nosys",
		"mount",
		"nosys",
		"csops",
		"csops_audittoken",
		"nosys",
		"nosys",
		"waitid",
		"nosys",
		"nosys",
		"nosys",
		"kdebug_typefilter",
		"kdebug_trace_string",
		"kdebug_trace64",
		"kdebug_trace",
		"setgid",
		"setegid",
		"seteuid",
		"sigreturn",
		"enosys",
		"thread_selfcounts",
		"fdatasync",
		"stat",
		"sys_fstat",
		"lstat",
		"pathconf",
		"sys_fpathconf",
		"nosys",
		"getrlimit",
		"setrlimit",
		"getdirentries",
		"mmap",
		"nosys",
		"lseek",
		"truncate",
		"ftruncate",
		"sysctl",
		"mlock",
		"munlock",
		"undelete",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"open_dprotected_np",
		"fsgetpath_ext",
		"nosys",
		"nosys",
		"getattrlist",
		"setattrlist",
		"getdirentriesattr",
		"exchangedata",
		"nosys",
		"searchfs",
		"delete",
		"copyfile",
		"fgetattrlist",
		"fsetattrlist",
		"poll",
		"nosys",
		"nosys",
		"nosys",
		"getxattr",
		"fgetxattr",
		"setxattr",
		"fsetxattr",
		"removexattr",
		"fremovexattr",
		"listxattr",
		"flistxattr",
		"fsctl",
		"initgroups",
		"posix_spawn",
		"ffsctl",
		"nosys",
		"nfsclnt",
		"fhopen",
		"nosys",
		"minherit",
		"semsys",
		"msgsys",
		"shmsys",
		"semctl",
		"semget",
		"semop",
		"nosys",
		"msgctl",
		"msgget",
		"msgsnd",
		"msgrcv",
		"shmat",
		"shmctl",
		"shmdt",
		"shmget",
		"shm_open",
		"shm_unlink",
		"sem_open",
		"sem_close",
		"sem_unlink",
		"sem_wait",
		"sem_trywait",
		"sem_post",
		"sys_sysctlbyname",
		"enosys",
		"enosys",
		"open_extended",
		"umask_extended",
		"stat_extended",
		"lstat_extended",
		"sys_fstat_extended",
		"chmod_extended",
		"fchmod_extended",
		"access_extended",
		"settid",
		"gettid",
		"setsgroups",
		"getsgroups",
		"setwgroups",
		"getwgroups",
		"mkfifo_extended",
		"mkdir_extended",
		"identitysvc",
		"shared_region_check_np",
		"nosys",
		"vm_pressure_monitor",
		"psynch_rw_longrdlock",
		"psynch_rw_yieldwrlock",
		"psynch_rw_downgrade",
		"psynch_rw_upgrade",
		"psynch_mutexwait",
		"psynch_mutexdrop",
		"psynch_cvbroad",
		"psynch_cvsignal",
		"psynch_cvwait",
		"psynch_rw_rdlock",
		"psynch_rw_wrlock",
		"psynch_rw_unlock",
		"psynch_rw_unlock2",
		"getsid",
		"settid_with_pid",
		"psynch_cvclrprepost",
		"aio_fsync",
		"aio_return",
		"aio_suspend",
		"aio_cancel",
		"aio_error",
		"aio_read",
		"aio_write",
		"lio_listio",
		"nosys",
		"iopolicysys",
		"process_policy",
		"mlockall",
		"munlockall",
		"nosys",
		"issetugid",
		"__pthread_kill",
		"__pthread_sigmask",
		"__sigwait",
		"__disable_threadsignal",
		"__pthread_markcancel",
		"__pthread_canceled",
		"nosys",
		"proc_info",
		"sendfile",
		"stat64",
		"sys_fstat64",
		"lstat64",
		"stat64_extended",
		"lstat64_extended",
		"sys_fstat64_extended",
		"getdirentries64",
		"statfs64",
		"fstatfs64",
		"getfsstat64",
		"__pthread_chdir",
		"__pthread_fchdir",
		"audit",
		"auditon",
		"nosys",
		"getauid",
		"setauid",
		"nosys",
		"nosys",
		"getaudit_addr",
		"setaudit_addr",
		"auditctl",
		"bsdthread_create",
		"bsdthread_terminate",
		"nosys",
		"nosys",
		"kqueue",
		"kevent",
		"lchown",
		"nosys",
		"bsdthread_register",
		"workq_open",
		"workq_kernreturn",
		"nosys",
		"nosys",
		"nosys",
		"kevent64",
		"__old_semwait_signal",
		"__old_semwait_signal_nocancel",
		"nosys",
		"nosys",
		"thread_selfid",
		"ledger",
		"kevent_qos",
		"kevent_id",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"__mac_execve",
		"__mac_syscall",
		"__mac_get_file",
		"__mac_set_file",
		"__mac_get_link",
		"__mac_set_link",
		"__mac_get_proc",
		"__mac_set_proc",
		"__mac_get_fd",
		"__mac_set_fd",
		"__mac_get_pid",
		"enosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"enosys",
		"enosys",
		"enosys",
		"pselect",
		"pselect_nocancel",
		"read_nocancel",
		"write_nocancel",
		"open_nocancel",
		"sys_close_nocancel",
		"wait4_nocancel",
		"recvmsg_nocancel",
		"sendmsg_nocancel",
		"recvfrom_nocancel",
		"accept_nocancel",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"msync_nocancel",
		"sys_fcntl_nocancel",
		"select_nocancel",
		"fsync_nocancel",
		"connect_nocancel",
		"nosys",
		"sigsuspend_nocancel",
		"readv_nocancel",
		"writev_nocancel",
		"sendto_nocancel",
		"nosys",
		"pread_nocancel",
		"pwrite_nocancel",
		"waitid_nocancel",
		"poll_nocancel",
		"msgsnd_nocancel",
		"msgrcv_nocancel",
		"nosys",
		"nosys",
		"sem_wait_nocancel",
		"aio_suspend_nocancel",
		"__sigwait_nocancel",
		"nosys",
		"__semwait_signal_nocancel",
		"__mac_mount",
		"__mac_get_mount",
		"nosys",
		"__mac_getfsstat",
		"fsgetpath",
		"audit_session_self",
		"audit_session_join",
		"sys_fileport_makeport",
		"sys_fileport_makefd",
		"audit_session_port",
		"pid_suspend",
		"pid_resume",
		"pid_hibernate",
		"nosys",
		"pid_shutdown_sockets",
		"nosys",
		"nosys",
		"shared_region_map_and_slide_np",
		"kas_info",
		"memorystatus_control",
		"nosys",
		"guarded_open_np",
		"guarded_close_np",
		"guarded_kqueue_np",
		"change_fdguard_np",
		"usrctl",
		"proc_rlimit_control",
		"connectx",
		"disconnectx",
		"peeloff",
		"socket_delegate",
		"nosys",
		"nosys",
		"nosys",
		"nosys",
		"telemetry",
		"proc_uuid_policy",
		"nosys",
		"memorystatus_get_level",
		"nosys",
		"system_override",
		"vfs_purge",
		"sfi_ctl",
		"sfi_pidctl",
		"coalition",
		"coalition_info",
		"enosys",
		"enosys",
		"necp_match_policy",
		"nosys",
		"getattrlistbulk",
		"clonefileat",
		"openat",
		"openat_nocancel",
		"renameat",
		"faccessat",
		"fchmodat",
		"fchownat",
		"fstatat",
		"fstatat64",
		"linkat",
		"unlinkat",
		"readlinkat",
		"symlinkat",
		"mkdirat",
		"getattrlistat",
		"proc_trace_log",
		"bsdthread_ctl",
		"openbyid_np",
		"recvmsg_x",
		"sendmsg_x",
		"nosys",
		"nosys",
		"thread_selfusage",
		"csrctl",
		"enosys",
		"guarded_open_dprotected_np",
		"guarded_write_np",
		"guarded_pwrite_np",
		"guarded_writev_np",
		"renameatx_np",
		"mremap_encrypted",
		"enosys",
		"netagent_trigger",
		"nosys",
		"stack_snapshot_with_config",
		"microstackshot",
		"enosys",
		"grab_pgo_data",
		"enosys",
		"persona",
		"enosys",
		"enosys",
		"mach_eventlink_signal",
		"mach_eventlink_wait_until",
		"mach_eventlink_signal_wait_until",
		"work_interval_ctl",
		"getentropy",
		"necp_open",
		"necp_client_action",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"enosys",
		"ulock_wait",
		"ulock_wake",
		"fclonefileat",
		"fs_snapshot",
		"enosys",
		"terminate_with_payload",
		"abort_with_payload",
		"necp_session_open",
		"necp_session_action",
		"enosys",
		"enosys",
		"setattrlistat",
		"net_qos_guideline",
		"fmount",
		"ntp_adjtime",
		"ntp_gettime",
		"os_fault_with_payload",
		"kqueue_workloop_ctl",
		"enosys",
		"__mach_bridge_remote_time",
		"coalition_ledger",
		"enosys",
		"log_data",
		"memorystatus_available_memory",
		"enosys",
		"shared_region_map_and_slide_2_np",
		"pivot_root",
		"task_inspect_for_pid",
		"task_read_for_pid",
		"sys_preadv",
		"sys_pwritev",
		"sys_preadv_nocancel",
		"sys_pwritev_nocancel",
		"ulock_wait2",
		"proc_info_extended_id",
	])

if __name__ == "__main__":
	main()
