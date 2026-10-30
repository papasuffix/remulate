#pragma once
 
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
 
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <unicorn/unicorn.h>
 
#pragma comment(lib, "advapi32.lib")
 
inline constexpr uint64_t PAGE_SIZE = 0x1000ULL;
inline constexpr uint64_t STACK_SIZE = 0x00100000ULL;
inline constexpr uint64_t STACK_GUARD_SIZE = PAGE_SIZE;
inline constexpr uint64_t STACK_SEARCH_START = 0x0000001000000000ULL;
 
inline constexpr uint64_t TEB_CLONE_SIZE = 0x2000ULL;
inline constexpr uint64_t LDR_CLONE_SIZE = 0x1000ULL;
inline constexpr uint64_t TLS_VECTOR_SIZE = 64ULL * sizeof(uint64_t);
inline constexpr uint64_t TLS_EXPANSION_VECTOR_SIZE = 1024ULL * sizeof(uint64_t);
inline constexpr uint64_t MAX_PROCESS_PARAMETERS_SIZE = 0x00100000ULL;
 
inline constexpr uint64_t TEB_STACK_BASE_OFFSET = 0x08;
inline constexpr uint64_t TEB_STACK_LIMIT_OFFSET = 0x10;
inline constexpr uint64_t TEB_SELF_OFFSET = 0x30;
inline constexpr uint64_t TEB_TLS_POINTER_OFFSET = 0x58;
inline constexpr uint64_t TEB_PEB_OFFSET = 0x60;
inline constexpr uint64_t TEB_DEALLOCATION_STACK_OFFSET = 0x1478;
inline constexpr uint64_t TEB_TLS_EXPANSION_SLOTS_OFFSET = 0x1780;
inline constexpr uint64_t PEB_LDR_OFFSET = 0x18;
inline constexpr uint64_t PEB_PROCESS_PARAMETERS_OFFSET = 0x20;
 
inline constexpr NTSTATUS STATUS_PENDING_VALUE = 0x00000103L;
inline constexpr NTSTATUS STATUS_INVALID_HANDLE_VALUE = 0xC0000008L;
inline constexpr NTSTATUS STATUS_INVALID_PARAMETER_VALUE = 0xC000000DL;
inline constexpr NTSTATUS STATUS_NO_MEMORY_VALUE = 0xC0000017L;
inline constexpr NTSTATUS STATUS_ACCESS_VIOLATION_VALUE = 0xC0000005L;
inline constexpr NTSTATUS STATUS_NOT_SUPPORTED_VALUE = 0xC00000BBL;
inline constexpr NTSTATUS STATUS_NOT_IMPLEMENTED_VALUE = 0xC0000002L;
inline constexpr NTSTATUS STATUS_UNSUCCESSFUL_VALUE = 0xC0000001L;
 
inline constexpr size_t MAX_NATIVE_ARGUMENTS = 16;
inline constexpr uint64_t MAX_MARSHALLED_BUFFER_SIZE = 64ULL * 1024ULL * 1024ULL;
inline constexpr uint64_t MAX_UNICODE_BYTES = 1ULL * 1024ULL * 1024ULL;
 
struct THREAD_BASIC_INFORMATION_LOCAL {
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
};
 
class emulator {
private:
	uc_engine* uc = nullptr;
	HANDLE remote = nullptr;
	HANDLE remote_thread = nullptr;
	HANDLE target_impersonation_token = nullptr;
	HMODULE local_ntdll = nullptr;
	DWORD remote_pid = 0;
	DWORD emulated_tid = 0;
 
	uint64_t stack_reservation_base = 0;
	uint64_t stack_limit = 0;
	uint64_t stack_base = 0;
	uint64_t return_sentinel = 0;
	uint64_t remote_teb_address = 0;
	uint64_t remote_peb_address = 0;
	bool hook_failed = false;
 
	struct mem_range {
		uint64_t base = 0;
		uint64_t size = 0;
 
		bool contains(uint64_t address) const {
			return address >= base && address - base < size;
		}
	};
 
	std::unordered_map<uint64_t, bool> mapped;
	std::unordered_map<uint64_t, bool> code_pages;
	std::unordered_map<uint64_t, bool> refreshed_this_call;
	std::unordered_set<uint64_t> dirty_remote_pages;
	std::vector<mem_range> private_ranges;
 
	enum class arg_kind {
		scalar,
		handle_in,
		handle_out,
		buffer_in,
		buffer_out,
		buffer_inout,
		unicode_string_in,
		object_attributes_in,
		io_status_block_out,
		client_id_in,
		large_integer_in,
		u32_out,
		u64_out,
		u64_inout,
		handle_array_in
	};
 
	struct arg_spec {
		arg_kind kind = arg_kind::scalar;
		int size_from_arg = -1;
		uint64_t fixed_size = 0;
		bool optional = false;
	};
 
	struct syscall_desc {
		std::string name;
		std::vector<arg_spec> args;
		int apc_routine_arg = -1;
		int io_status_block_arg = -1;
		int wait_handle_arg = -1;
		bool complete_pending = false;
	};
 
	struct local_block {
		std::unique_ptr<uint8_t[]> bytes;
		size_t size = 0;
	};
 
	struct copy_back {
		uint64_t guest_address = 0;
		void* local_address = nullptr;
		size_t size = 0;
		bool relocate_internal_pointers = false;
	};
 
	struct output_handle {
		uint64_t guest_address = 0;
		HANDLE* local_address = nullptr;
	};
 
	struct marshalled_call {
		std::array<uint64_t, MAX_NATIVE_ARGUMENTS> guest_args{};
		std::array<uint64_t, MAX_NATIVE_ARGUMENTS> local_args{};
		std::vector<local_block> blocks;
		std::vector<copy_back> copy_backs;
		std::vector<output_handle> output_handles;
		std::vector<HANDLE> temporary_handles;
 
		void* allocate(size_t size) {
			if (size == 0)
				return nullptr;
 
			local_block block{};
			block.bytes.reset(new (std::nothrow) uint8_t[size]{});
			if (!block.bytes)
				return nullptr;
 
			block.size = size;
			void* result = block.bytes.get();
			blocks.push_back(std::move(block));
			return result;
		}
	};
 
	std::unordered_map<uint32_t, std::string> syscall_names_by_id;
	std::unordered_map<std::string, uint64_t> syscall_addresses_by_name;
	std::unordered_map<std::string, syscall_desc> syscall_descriptors;
	std::unordered_map<uint64_t, HANDLE> emulated_handles;
	std::unordered_set<std::string> reported_missing_syscalls;
 
	static uint64_t page_align_down(uint64_t address) {
		return address & ~(PAGE_SIZE - 1);
	}
 
	static bool align_up(uint64_t value, uint64_t alignment, uint64_t& result) {
		if (value > (std::numeric_limits<uint64_t>::max)() - (alignment - 1))
			return false;
 
		result = (value + alignment - 1) & ~(alignment - 1);
		return true;
	}
 
	bool is_private(uint64_t address) const {
		for (const auto& range : private_ranges) {
			if (range.contains(address))
				return true;
		}
 
		return false;
	}
 
	bool read_remote(uint64_t address, void* buffer, size_t size) const {
		SIZE_T bytes_read = 0;
		return ReadProcessMemory(remote, (void*)address, buffer, size, &bytes_read) != FALSE && bytes_read == size;
	}
 
	bool write_remote(uint64_t address, const void* buffer, size_t size) const {
		SIZE_T bytes_written = 0;
		return WriteProcessMemory(remote, (void*)address, buffer, size, &bytes_written) != FALSE && bytes_written == size;
	}
 
	bool write_emulated(uint64_t address, const void* buffer, size_t size) {
		const uc_err err = uc_mem_write(uc, address, buffer, size);
		if (err != UC_ERR_OK)
			return printf("error: uc_mem_write at 0x%llx failed: %s\n", address, uc_strerror(err)), false;
 
		return true;
	}
 
	bool sync_page_from_remote(uint64_t page_address) {
		page_address = page_align_down(page_address);
		std::vector<uint8_t> page(PAGE_SIZE);
		if (!read_remote(page_address, page.data(), page.size()))
			return false;
 
		if (!mapped.count(page_address)) {
			const uc_err map_err = uc_mem_map(uc, page_address, PAGE_SIZE, UC_PROT_ALL);
			if (map_err != UC_ERR_OK)
				return false;
 
			mapped[page_address] = true;
		}
 
		return write_emulated(page_address, page.data(), page.size());
	}
 
	bool ensure_guest_range(uint64_t address, size_t size) {
		if (!address || !size || address > (std::numeric_limits<uint64_t>::max)() - size)
			return false;
 
		const uint64_t first = page_align_down(address);
		uint64_t end = 0;
		if (!align_up(address + size, PAGE_SIZE, end))
			return false;
 
		for (uint64_t page = first; page < end; page += PAGE_SIZE) {
			if (mapped.count(page))
				continue;
 
			if (is_private(page) || !sync_page_from_remote(page))
				return false;
		}
		return true;
	}
 
	bool read_guest(uint64_t address, void* buffer, size_t size) {
		if (!ensure_guest_range(address, size))
			return false;
 
		return uc_mem_read(uc, address, buffer, size) == UC_ERR_OK;
	}
 
	bool write_guest(uint64_t address, const void* buffer, size_t size) {
		if (!ensure_guest_range(address, size) || !write_emulated(address, buffer, size))
			return false;
 
		if (!is_private(address) && !write_remote(address, buffer, size))
			return false;
 
		return true;
	}
 
	bool flush_dirty_remote_pages() {
		std::vector<uint8_t> page(PAGE_SIZE);
		for (const uint64_t address : dirty_remote_pages) {
			if (uc_mem_read(uc, address, page.data(), page.size()) != UC_ERR_OK || !write_remote(address, page.data(), page.size()))
				return false;
		}
 
		dirty_remote_pages.clear();
		return true;
	}
 
	bool map_private_remote_range(uint64_t address, uint64_t size) {
		if (address == 0 || size == 0 || address > (std::numeric_limits<uint64_t>::max)() - size)
			return false;
 
		const uint64_t first_page = page_align_down(address);
		uint64_t end = 0;
		if (!align_up(address + size, PAGE_SIZE, end) || end <= first_page)
			return false;
 
		for (uint64_t page = first_page; page < end; page += PAGE_SIZE) {
			if (!sync_page_from_remote(page))
				return false;
		}
 
		private_ranges.push_back({ first_page, end - first_page });
		return true;
	}
 
	bool find_free_stack_region(uint64_t reservation_size, uint64_t& result) const {
		SYSTEM_INFO system_info{};
		GetSystemInfo(&system_info);
		const auto maximum_address = (uint64_t)system_info.lpMaximumApplicationAddress;
		uint64_t cursor = STACK_SEARCH_START;
 
		while (cursor < maximum_address) {
			MEMORY_BASIC_INFORMATION mbi{};
			if (VirtualQueryEx(remote, (void*)cursor, &mbi, sizeof(mbi)) != sizeof(mbi))
				return false;
 
			const auto region_base = (uint64_t)mbi.BaseAddress;
			const auto region_size = mbi.RegionSize;
			if (region_size == 0 || region_base > (std::numeric_limits<uint64_t>::max)() - region_size)
				return false;
 
			const uint64_t region_end = region_base + region_size;
			if (mbi.State == MEM_FREE) {
				uint64_t candidate = 0;
				if (align_up((std::max)(cursor, region_base), PAGE_SIZE, candidate) && candidate <= region_end && reservation_size <= region_end - candidate) {
					result = candidate;
					return true;
				}
			}
 
			if (region_end <= cursor)
				return false;
 
			cursor = region_end;
		}
 
		return false;
	}
 
	bool setup_stack() {
		const uint64_t reservation_size = STACK_GUARD_SIZE + STACK_SIZE + STACK_GUARD_SIZE;
		if (!find_free_stack_region(reservation_size, stack_reservation_base))
			return printf("error: could not find a private stack address range\n"), false;
 
		stack_limit = stack_reservation_base + STACK_GUARD_SIZE;
		stack_base = stack_limit + STACK_SIZE;
		return_sentinel = stack_base;
 
		const uc_err err = uc_mem_map(uc, stack_limit, STACK_SIZE, UC_PROT_ALL);
		if (err != UC_ERR_OK)
			return printf("error: failed to map private stack: %s\n", uc_strerror(err)), false;
 
		for (uint64_t page = stack_limit; page < stack_base; page += PAGE_SIZE)
			mapped[page] = true;
 
		private_ranges.push_back({ stack_reservation_base, reservation_size });
		return true;
	}
 
	bool setup_environment(DWORD requested_tid) {
		using NtQueryInformationThread_fn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
		local_ntdll = GetModuleHandleW(L"ntdll.dll");
		static const auto NtQueryInformationThread = (NtQueryInformationThread_fn)GetProcAddress(local_ntdll, "NtQueryInformationThread");
		if (!NtQueryInformationThread)
			return printf("error: failed to find NtQueryInformationThread\n"), false;
 
		const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return printf("error: CreateToolhelp32Snapshot failed with %lu\n", GetLastError()), false;
 
		THREADENTRY32 entry{};
		entry.dwSize = sizeof(entry);
		bool found = false;
		if (Thread32First(snapshot, &entry)) {
			do {
				if (entry.th32OwnerProcessID == remote_pid && (requested_tid == 0 || entry.th32ThreadID == requested_tid)) {
					emulated_tid = entry.th32ThreadID;
					found = true;
					break;
				}
			} while (Thread32Next(snapshot, &entry));
		}
		CloseHandle(snapshot);
 
		if (!found)
			return printf("error: no suitable thread found in target process\n"), false;
 
		remote_thread = OpenThread(THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, emulated_tid);
		if (!remote_thread)
			return printf("error: OpenThread(%lu) failed (%lu)\n", emulated_tid, GetLastError()), false;
 
		THREAD_BASIC_INFORMATION_LOCAL tbi{};
		const NTSTATUS status = NtQueryInformationThread(remote_thread, 0, &tbi, sizeof(tbi), nullptr);
		if (status < 0 || !tbi.TebBaseAddress)
			return printf("error: NtQueryInformationThread failed 0x%08lx\n", status), false;
 
		remote_teb_address = (uint64_t)tbi.TebBaseAddress;
		uint64_t remote_tls = 0;
		uint64_t remote_tls_expansion = 0;
 
		if (!read_remote(remote_teb_address + TEB_PEB_OFFSET, &remote_peb_address, sizeof(remote_peb_address)) || !remote_peb_address)
			return printf("error: failed to obtain the target PEB\n"), false;
 
		read_remote(remote_teb_address + TEB_TLS_POINTER_OFFSET, &remote_tls, sizeof(remote_tls));
		read_remote(remote_teb_address + TEB_TLS_EXPANSION_SLOTS_OFFSET, &remote_tls_expansion, sizeof(remote_tls_expansion));
 
		if (!map_private_remote_range(remote_teb_address, TEB_CLONE_SIZE) || !map_private_remote_range(remote_peb_address, PAGE_SIZE))
			return false;
 
		uint64_t remote_ldr = 0;
		if (!read_remote(remote_peb_address + PEB_LDR_OFFSET, &remote_ldr, sizeof(remote_ldr)))
			return false;
		if (remote_ldr && !map_private_remote_range(remote_ldr, LDR_CLONE_SIZE))
			return false;
 
		uint64_t remote_process_parameters = 0;
		if (!read_remote(remote_peb_address + PEB_PROCESS_PARAMETERS_OFFSET, &remote_process_parameters, sizeof(remote_process_parameters)))
			return false;
 
		if (remote_process_parameters) {
			ULONG maximum_length = 0;
			if (!read_remote(remote_process_parameters, &maximum_length, sizeof(maximum_length)))
				return false;
 
			uint64_t clone_size = (std::max)((uint64_t)maximum_length, PAGE_SIZE);
			if (clone_size > MAX_PROCESS_PARAMETERS_SIZE)
				return printf("error: unreasonable process parameters size: 0x%llx\n", clone_size), false;
 
			if (!map_private_remote_range(remote_process_parameters, clone_size))
				return false;
		}
 
		if (remote_tls && !map_private_remote_range(remote_tls, TLS_VECTOR_SIZE))
			return false;
		if (remote_tls_expansion && !map_private_remote_range(remote_tls_expansion, TLS_EXPANSION_VECTOR_SIZE))
			return false;
 
		const uint64_t teb_self = remote_teb_address;
		const uint64_t deallocation_stack = stack_reservation_base;
		if (!write_emulated(remote_teb_address + TEB_SELF_OFFSET, &teb_self, sizeof(teb_self)) ||
			!write_emulated(remote_teb_address + TEB_STACK_BASE_OFFSET, &stack_base, sizeof(stack_base)) ||
			!write_emulated(remote_teb_address + TEB_STACK_LIMIT_OFFSET, &stack_limit, sizeof(stack_limit)) ||
			!write_emulated(remote_teb_address + TEB_DEALLOCATION_STACK_OFFSET, &deallocation_stack, sizeof(deallocation_stack)))
			return false;
 
		const uint64_t gs_base = remote_teb_address;
		if (uc_reg_write(uc, UC_X86_REG_GS_BASE, &gs_base) != UC_ERR_OK)
			return printf("error: failed to set GS base\n"), false;
 
		uc_x86_msr msr{};
		msr.rid = 0xC0000101;
		msr.value = remote_teb_address;
		if (uc_reg_write(uc, UC_X86_REG_MSR, &msr) != UC_ERR_OK)
			return printf("error: failed to set IA32_GS_BASE\n"), false;
 
		HANDLE source_token = nullptr;
		if (!OpenThreadToken(remote_thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &source_token))
			OpenProcessToken(remote, TOKEN_QUERY | TOKEN_DUPLICATE, &source_token);
 
		if (source_token) {
			DuplicateTokenEx(source_token, TOKEN_QUERY | TOKEN_IMPERSONATE, nullptr, SecurityImpersonation, TokenImpersonation, &target_impersonation_token);
			CloseHandle(source_token);
		}
 
		printf("environment ready: TID=%lu TEB=0x%llx PEB=0x%llx StackLimit=0x%llx StackBase=0x%llx\n", emulated_tid, remote_teb_address, remote_peb_address, stack_limit, stack_base);
		return true;
	}
 
	bool refresh_dynamic_environment() {
		return sync_page_from_remote(remote_peb_address);
	}
 
	bool find_remote_module(const wchar_t* wanted_name, uint64_t& base, uint32_t& size) const {
		const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, remote_pid);
		if (snapshot == INVALID_HANDLE_VALUE)
			return false;
 
		MODULEENTRY32W module{};
		module.dwSize = sizeof(module);
		bool found = false;
		if (Module32FirstW(snapshot, &module)) {
			do {
				if (_wcsicmp(module.szModule, wanted_name) == 0) {
					base = (uint64_t)module.modBaseAddr;
					size = module.modBaseSize;
					found = true;
					break;
				}
			} while (Module32NextW(snapshot, &module));
		}
 
		CloseHandle(snapshot);
		return found;
	}
 
	bool read_remote_ascii(uint64_t address, std::string& result, size_t maximum = 256) const {
		result.clear();
		for (size_t i = 0; i < maximum; ++i) {
			char c = 0;
			if (!read_remote(address + i, &c, sizeof(c)))
				return false;
			if (!c)
				return true;
			result.push_back(c);
		}
		return false;
	}
 
	bool extract_syscall_id(uint64_t module_base, uint32_t module_size, uint64_t function_address, uint32_t& id) const {
		for (int depth = 0; depth < 3; ++depth) {
			std::array<uint8_t, 96> code{};
			if (!read_remote(function_address, code.data(), code.size()))
				return false;
 
			if (code[0] == 0xE9) {
				int32_t displacement = 0;
				memcpy(&displacement, &code[1], sizeof(displacement));
 
				const uint64_t destination = function_address + 5 + displacement;
				if (destination < module_base || destination >= module_base + module_size)
					return false;
 
				function_address = destination;
				continue;
			}
 
			for (size_t i = 0; i + 7 < code.size(); ++i) {
				if (code[i] != 0xB8)
					continue;
 
				uint32_t candidate = 0;
				memcpy(&candidate, &code[i + 1], sizeof(candidate));
				const size_t search_end = (std::min)(code.size() - 1, i + 40);
				for (size_t j = i + 5; j < search_end; ++j) {
					if (code[j] == 0x0F && code[j + 1] == 0x05) {
						id = candidate;
						return true;
					}
				}
			}
 
			return false;
		}
 
		return false;
	}
 
	bool discover_syscalls() {
		uint64_t module_base = 0;
		uint32_t module_size = 0;
		if (!find_remote_module(L"ntdll.dll", module_base, module_size))
			return printf("error: target ntdll.dll was not found\n"), false;
 
		IMAGE_DOS_HEADER dos{};
		IMAGE_NT_HEADERS64 nt{};
		if (!read_remote(module_base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || !read_remote(module_base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE)
			return printf("error: invalid target ntdll image\n"), false;
 
		const auto& directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		IMAGE_EXPORT_DIRECTORY exports{};
		if (!directory.VirtualAddress || !directory.Size || !read_remote(module_base + directory.VirtualAddress, &exports, sizeof(exports)))
			return printf("error: target ntdll has no readable export directory\n"), false;
 
		if (exports.NumberOfNames > 100000 || exports.NumberOfFunctions > 100000)
			return printf("error: unreasonable ntdll export count\n"), false;
 
		std::vector<uint32_t> names(exports.NumberOfNames);
		std::vector<uint16_t> ordinals(exports.NumberOfNames);
		std::vector<uint32_t> functions(exports.NumberOfFunctions);
		if (!read_remote(module_base + exports.AddressOfNames, names.data(), names.size() * sizeof(uint32_t)) ||
			!read_remote(module_base + exports.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(uint16_t)) ||
			!read_remote(module_base + exports.AddressOfFunctions, functions.data(), functions.size() * sizeof(uint32_t)))
			return printf("error: failed to read target ntdll exports\n"), false;
 
		for (size_t i = 0; i < names.size(); ++i) {
			std::string export_name;
			if (!read_remote_ascii(module_base + names[i], export_name) || export_name.size() < 3)
				continue;
 
			if (export_name.rfind("Nt", 0) != 0 && export_name.rfind("Zw", 0) != 0)
				continue;
 
			if (ordinals[i] >= functions.size())
				continue;
 
			uint32_t id = 0;
			if (!extract_syscall_id(module_base, module_size, module_base + functions[ordinals[i]], id))
				continue;
 
			std::string canonical = export_name;
			if (canonical.rfind("Zw", 0) == 0)
				canonical.replace(0, 2, "Nt");
 
			auto existing = syscall_names_by_id.find(id);
			if (existing == syscall_names_by_id.end() || export_name.rfind("Nt", 0) == 0)
				syscall_names_by_id[id] = canonical;
 
			if (!syscall_addresses_by_name.count(canonical) || export_name.rfind("Nt", 0) == 0)
				syscall_addresses_by_name[canonical] = module_base + functions[ordinals[i]];
		}
 
		printf("discovered %zu target ntdll syscall IDs\n", syscall_names_by_id.size());
		return !syscall_names_by_id.empty();
	}
 
	static arg_spec scalar() { return { arg_kind::scalar }; }
	static arg_spec handle(bool optional = false) { return { arg_kind::handle_in, -1, 0, optional }; }
	static arg_spec out_handle() { return { arg_kind::handle_out }; }
	static arg_spec in_buffer(int size_arg, bool optional = false) { return { arg_kind::buffer_in, size_arg, 0, optional }; }
	static arg_spec out_buffer(int size_arg, bool optional = false) { return { arg_kind::buffer_out, size_arg, 0, optional }; }
	static arg_spec inout_buffer(int size_arg, bool optional = false) { return { arg_kind::buffer_inout, size_arg, 0, optional }; }
	static arg_spec unicode(bool optional = false) { return { arg_kind::unicode_string_in, -1, 0, optional }; }
	static arg_spec object_attributes(bool optional = false) { return { arg_kind::object_attributes_in, -1, 0, optional }; }
	static arg_spec iosb() { return { arg_kind::io_status_block_out }; }
	static arg_spec client_id(bool optional = false) { return { arg_kind::client_id_in, -1, 0, optional }; }
	static arg_spec large_integer(bool optional = false) { return { arg_kind::large_integer_in, -1, 0, optional }; }
	static arg_spec out_u32(bool optional = false) { return { arg_kind::u32_out, -1, 0, optional }; }
	static arg_spec out_u64(bool optional = false) { return { arg_kind::u64_out, -1, 0, optional }; }
	static arg_spec inout_u64(bool optional = false) { return { arg_kind::u64_inout, -1, 0, optional }; }
	static arg_spec handle_array(int count_arg) { return { arg_kind::handle_array_in, count_arg }; }
 
	void add_syscall(const char* name, std::initializer_list<arg_spec> args, int apc_arg = -1, int iosb_arg = -1, int wait_arg = -1, bool complete_pending = false) {
		syscall_desc desc{};
		desc.name = name;
		desc.args.assign(args.begin(), args.end());
		desc.apc_routine_arg = apc_arg;
		desc.io_status_block_arg = iosb_arg;
		desc.wait_handle_arg = wait_arg;
		desc.complete_pending = complete_pending;
		syscall_descriptors.emplace(desc.name, std::move(desc));
	}
 
	void initialize_syscall_descriptors() {
		add_syscall("NtAllocateVirtualMemory", { handle(), inout_u64(), scalar(), inout_u64(), scalar(), scalar() });
		add_syscall("NtFreeVirtualMemory", { handle(), inout_u64(), inout_u64(), scalar() });
		add_syscall("NtProtectVirtualMemory", { handle(), inout_u64(), inout_u64(), scalar(), out_u32() });
		add_syscall("NtQueryVirtualMemory", { handle(), scalar(), scalar(), out_buffer(4), scalar(), out_u64(true) });
		add_syscall("NtReadVirtualMemory", { handle(), scalar(), out_buffer(3), scalar(), out_u64(true) });
		add_syscall("NtWriteVirtualMemory", { handle(), scalar(), in_buffer(3), scalar(), out_u64(true) });
		add_syscall("NtCreateSection", { out_handle(), scalar(), object_attributes(true), large_integer(true), scalar(), scalar(), handle(true) });
		add_syscall("NtOpenSection", { out_handle(), scalar(), object_attributes() });
		add_syscall("NtMapViewOfSection", { handle(), handle(), inout_u64(), scalar(), scalar(), inout_u64(true), inout_u64(), scalar(), scalar(), scalar() });
		add_syscall("NtUnmapViewOfSection", { handle(), scalar() });
		add_syscall("NtQuerySection", { handle(), scalar(), out_buffer(3), scalar(), out_u64(true) });
 
		add_syscall("NtQueryObject", { handle(), scalar(), out_buffer(3), scalar(), out_u32(true) });
		add_syscall("NtOpenProcess", { out_handle(), scalar(), object_attributes(), client_id() });
		add_syscall("NtOpenThread", { out_handle(), scalar(), object_attributes(), client_id() });
		add_syscall("NtQueryInformationProcess", { handle(), scalar(), out_buffer(3), scalar(), out_u32(true) });
		add_syscall("NtSetInformationProcess", { handle(), scalar(), in_buffer(3), scalar() });
		add_syscall("NtQueryInformationThread", { handle(), scalar(), out_buffer(3), scalar(), out_u32(true) });
		add_syscall("NtSetInformationThread", { handle(), scalar(), in_buffer(3), scalar() });
		add_syscall("NtQuerySystemInformation", { scalar(), out_buffer(2), scalar(), out_u32(true) });
 
		add_syscall("NtQuerySystemTime", { out_u64() });
		add_syscall("NtQueryPerformanceCounter", { out_u64(), out_u64(true) });
		add_syscall("NtDelayExecution", { scalar(), large_integer() });
		add_syscall("NtWaitForSingleObject", { handle(), scalar(), large_integer(true) });
		add_syscall("NtWaitForMultipleObjects", { scalar(), handle_array(0), scalar(), scalar(), large_integer(true) });
		add_syscall("NtCreateEvent", { out_handle(), scalar(), object_attributes(true), scalar(), scalar() });
		add_syscall("NtOpenEvent", { out_handle(), scalar(), object_attributes() });
		add_syscall("NtSetEvent", { handle(), out_u32(true) });
		add_syscall("NtResetEvent", { handle(), out_u32(true) });
		add_syscall("NtClearEvent", { handle() });
		add_syscall("NtPulseEvent", { handle(), out_u32(true) });
		add_syscall("NtCreateMutant", { out_handle(), scalar(), object_attributes(true), scalar() });
		add_syscall("NtOpenMutant", { out_handle(), scalar(), object_attributes() });
		add_syscall("NtReleaseMutant", { handle(), out_u32(true) });
		add_syscall("NtCreateSemaphore", { out_handle(), scalar(), object_attributes(true), scalar(), scalar() });
		add_syscall("NtOpenSemaphore", { out_handle(), scalar(), object_attributes() });
		add_syscall("NtReleaseSemaphore", { handle(), scalar(), out_u32(true) });
 
		add_syscall("NtCreateFile", { out_handle(), scalar(), object_attributes(), iosb(), large_integer(true), scalar(), scalar(), scalar(), scalar(), in_buffer(10, true), scalar() });
		add_syscall("NtOpenFile", { out_handle(), scalar(), object_attributes(), iosb(), scalar(), scalar() });
		add_syscall("NtQueryAttributesFile", { object_attributes(), {arg_kind::buffer_out, -1, 40, false} });
		add_syscall("NtQueryFullAttributesFile", { object_attributes(), {arg_kind::buffer_out, -1, 56, false} });
		add_syscall("NtReadFile", { handle(), handle(true), scalar(), scalar(), iosb(), out_buffer(6), scalar(), large_integer(true), {arg_kind::buffer_in, -1, sizeof(ULONG), true} }, 2, 4, 1, true);
		add_syscall("NtWriteFile", { handle(), handle(true), scalar(), scalar(), iosb(), in_buffer(6), scalar(), large_integer(true), {arg_kind::buffer_in, -1, sizeof(ULONG), true} }, 2, 4, 1, true);
		add_syscall("NtQueryInformationFile", { handle(), iosb(), out_buffer(3), scalar(), scalar() }, -1, 1, 0, true);
		add_syscall("NtSetInformationFile", { handle(), iosb(), in_buffer(3), scalar(), scalar() }, -1, 1, 0, true);
		add_syscall("NtQueryVolumeInformationFile", { handle(), iosb(), out_buffer(3), scalar(), scalar() }, -1, 1, 0, true);
		add_syscall("NtQueryDirectoryFile", { handle(), handle(true), scalar(), scalar(), iosb(), out_buffer(6), scalar(), scalar(), scalar(), unicode(true), scalar() }, 2, 4, 1, true);
		add_syscall("NtDeviceIoControlFile", { handle(), handle(true), scalar(), scalar(), iosb(), scalar(), in_buffer(7, true), scalar(), out_buffer(9, true), scalar() }, 2, 4, 1, true);
		add_syscall("NtFsControlFile", { handle(), handle(true), scalar(), scalar(), iosb(), scalar(), in_buffer(7, true), scalar(), out_buffer(9, true), scalar() }, 2, 4, 1, true);
		add_syscall("NtFlushBuffersFile", { handle(), iosb() }, -1, 1, 0, true);
 
		add_syscall("NtOpenKey", { out_handle(), scalar(), object_attributes() });
		add_syscall("NtOpenKeyEx", { out_handle(), scalar(), object_attributes(), scalar() });
		add_syscall("NtCreateKey", { out_handle(), scalar(), object_attributes(), scalar(), unicode(true), scalar(), out_u32(true) });
		add_syscall("NtQueryKey", { handle(), scalar(), out_buffer(3), scalar(), out_u32() });
		add_syscall("NtEnumerateKey", { handle(), scalar(), scalar(), out_buffer(4), scalar(), out_u32() });
		add_syscall("NtEnumerateValueKey", { handle(), scalar(), scalar(), out_buffer(4), scalar(), out_u32() });
		add_syscall("NtQueryValueKey", { handle(), unicode(), scalar(), out_buffer(4), scalar(), out_u32() });
		add_syscall("NtSetValueKey", { handle(), unicode(), scalar(), scalar(), in_buffer(5), scalar() });
		add_syscall("NtDeleteValueKey", { handle(), unicode() });
		add_syscall("NtDeleteKey", { handle() });
		add_syscall("NtFlushKey", { handle() });
	}
 
	NTSTATUS win32_error_to_ntstatus(DWORD error) const {
		using RtlNtStatusFromDosError_fn = NTSTATUS(NTAPI*)(ULONG);
		static const auto convert = (RtlNtStatusFromDosError_fn)GetProcAddress(local_ntdll, "RtlNtStatusFromDosError");
		return convert ? convert(error) : STATUS_UNSUCCESSFUL_VALUE;
	}
 
	bool resolve_input_handle(uint64_t guest_handle, marshalled_call& call, HANDLE& local_handle) {
		if (!guest_handle) {
			local_handle = nullptr;
			return true;
		}
 
		if (guest_handle == -1LL) {
			local_handle = remote;
			return true;
		}
 
		if (guest_handle == -2LL) {
			local_handle = remote_thread;
			return true;
		}
 
		if (const auto it = emulated_handles.find(guest_handle); it != emulated_handles.end()) {
			local_handle = it->second;
			return true;
		}
 
		HANDLE duplicate = nullptr;
		if (!DuplicateHandle(remote, (HANDLE)guest_handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
			return false;
 
		call.temporary_handles.push_back(duplicate);
		local_handle = duplicate;
		return true;
	}
 
	bool publish_output_handle(HANDLE local_handle, uint64_t& guest_handle) {
		if (!local_handle)
			return false;
 
		HANDLE target_handle = nullptr;
		if (!DuplicateHandle(GetCurrentProcess(), local_handle, remote, &target_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
			return false;
 
		guest_handle = (uint64_t)target_handle;
		emulated_handles[guest_handle] = local_handle;
		return true;
	}
 
	NTSTATUS close_guest_handle(uint64_t guest_handle) {
		if (!guest_handle || guest_handle == -1LL || guest_handle == -2LL)
			return STATUS_INVALID_HANDLE_VALUE;
 
		HANDLE duplicate = nullptr;
		if (!DuplicateHandle(remote, (HANDLE)guest_handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
			return win32_error_to_ntstatus(GetLastError());
 
		CloseHandle(duplicate);
		if (const auto it = emulated_handles.find(guest_handle); it != emulated_handles.end()) {
			CloseHandle(it->second);
			emulated_handles.erase(it);
		}
 
		return 0;
	}
 
	bool marshal_unicode_string(marshalled_call& call, uint64_t guest_address, UNICODE_STRING*& local_string) {
		UNICODE_STRING source{};
		if (!read_guest(guest_address, &source, sizeof(source)))
			return false;
 
		if (source.Length > source.MaximumLength || source.MaximumLength > MAX_UNICODE_BYTES || (source.Length & 1))
			return false;
 
		local_string = (UNICODE_STRING*)call.allocate(sizeof(UNICODE_STRING));
		if (!local_string)
			return false;
 
		*local_string = source;
 
		if (!source.Buffer || !source.MaximumLength) {
			local_string->Buffer = nullptr;
			return source.Length == 0;
		}
 
		const size_t allocation_size = source.MaximumLength + sizeof(wchar_t);
		auto local_buffer = (wchar_t*)call.allocate(allocation_size);
		if (!local_buffer || !read_guest((uint64_t)source.Buffer, local_buffer, source.Length))
			return false;
 
		local_string->Buffer = local_buffer;
		return true;
	}
 
	bool clone_sid(marshalled_call& call, uint64_t guest_address, PSID& local_sid) {
		struct sid_header {
			BYTE revision;
			BYTE sub_authority_count;
			SID_IDENTIFIER_AUTHORITY identifier_authority;
		};
 
		sid_header header{};
		if (!read_guest(guest_address, &header, sizeof(header)))
			return false;
 
		const size_t size = sizeof(header) + header.sub_authority_count * sizeof(DWORD);
		if (size > MAX_UNICODE_BYTES)
			return false;
 
		local_sid = call.allocate(size);
		return local_sid && read_guest(guest_address, local_sid, size);
	}
 
	bool clone_acl(marshalled_call& call, uint64_t guest_address, PACL& local_acl) {
		ACL header{};
		if (!read_guest(guest_address, &header, sizeof(header)) || header.AclSize < sizeof(ACL) || header.AclSize > MAX_UNICODE_BYTES)
			return false;
 
		local_acl = (PACL)call.allocate(header.AclSize);
		return local_acl && read_guest(guest_address, local_acl, header.AclSize);
	}
 
	bool marshal_security_descriptor(marshalled_call& call, uint64_t guest_address, PVOID& local_descriptor) {
		SECURITY_DESCRIPTOR_RELATIVE relative{};
		if (!read_guest(guest_address, &relative, sizeof(relative)))
			return false;
 
		if (relative.Control & SE_SELF_RELATIVE) {
			size_t size = sizeof(relative);
			auto include_sid = [&](DWORD offset) -> bool {
				if (!offset)
					return true;
 
				struct sid_header {
					BYTE revision;
					BYTE sub_authority_count;
					SID_IDENTIFIER_AUTHORITY identifier_authority;
				} header{};
				if (!read_guest(guest_address + offset, &header, sizeof(header)))
					return false;
 
				const size_t end = offset + sizeof(header) + header.sub_authority_count * sizeof(DWORD);
				size = (std::max)(size, end);
				return size <= MAX_UNICODE_BYTES;
			};
 
			auto include_acl = [&](DWORD offset) -> bool {
				if (!offset)
					return true;
 
				ACL header{};
				if (!read_guest(guest_address + offset, &header, sizeof(header)) || header.AclSize < sizeof(ACL))
					return false;
 
				const size_t end = offset + header.AclSize;
				size = (std::max)(size, end);
				return size <= MAX_UNICODE_BYTES;
			};
 
			if (!include_sid(relative.Owner) || !include_sid(relative.Group) || !include_acl(relative.Sacl) || !include_acl(relative.Dacl))
				return false;
 
			local_descriptor = call.allocate(size);
			return local_descriptor && read_guest(guest_address, local_descriptor, size);
		}
 
		SECURITY_DESCRIPTOR absolute{};
		if (!read_guest(guest_address, &absolute, sizeof(absolute)))
			return false;
		auto local = (SECURITY_DESCRIPTOR*)call.allocate(sizeof(absolute));
		if (!local)
			return false;
		*local = absolute;
		if (absolute.Owner && !clone_sid(call, (uint64_t)absolute.Owner, local->Owner))
			return false;
		if (absolute.Group && !clone_sid(call, (uint64_t)absolute.Group, local->Group))
			return false;
		if (absolute.Sacl && !clone_acl(call, (uint64_t)absolute.Sacl, local->Sacl))
			return false;
		if (absolute.Dacl && !clone_acl(call, (uint64_t)absolute.Dacl, local->Dacl))
			return false;
 
		local_descriptor = local;
		return true;
	}
 
	bool marshal_object_attributes(marshalled_call& call, uint64_t guest_address, OBJECT_ATTRIBUTES*& local_attributes) {
		OBJECT_ATTRIBUTES source{};
		if (!read_guest(guest_address, &source, sizeof(source)) || source.Length < sizeof(OBJECT_ATTRIBUTES))
			return false;
 
		local_attributes = (OBJECT_ATTRIBUTES*)call.allocate(sizeof(OBJECT_ATTRIBUTES));
		if (!local_attributes)
			return false;
 
		*local_attributes = source;
		local_attributes->Length = sizeof(OBJECT_ATTRIBUTES);
 
		if (source.RootDirectory) {
			HANDLE root = nullptr;
			if (!resolve_input_handle((uint64_t)source.RootDirectory, call, root))
				return false;
 
			local_attributes->RootDirectory = root;
		}
 
		if (source.ObjectName) {
			UNICODE_STRING* object_name = nullptr;
			if (!marshal_unicode_string(call, (uint64_t)source.ObjectName, object_name))
				return false;
 
			local_attributes->ObjectName = object_name;
		}
 
		if (source.SecurityDescriptor) {
			PVOID descriptor = nullptr;
			if (!marshal_security_descriptor(call, (uint64_t)source.SecurityDescriptor, descriptor))
				return false;
 
			local_attributes->SecurityDescriptor = descriptor;
		}
 
		if (source.SecurityQualityOfService) {
			ULONG length = 0;
			if (!read_guest((uint64_t)source.SecurityQualityOfService, &length, sizeof(length)) || length < sizeof(ULONG) || length > 0x1000)
				return false;
 
			void* qos = call.allocate(length);
			if (!qos || !read_guest((uint64_t)source.SecurityQualityOfService, qos, length))
				return false;
 
			local_attributes->SecurityQualityOfService = qos;
		}
 
		return true;
	}
 
	bool marshal_argument(marshalled_call& call, size_t index, const arg_spec& spec, NTSTATUS& failure) {
		const uint64_t guest_value = call.guest_args[index];
		call.local_args[index] = guest_value;
 
		if (!guest_value && spec.optional) {
			call.local_args[index] = 0;
			return true;
		}
 
		auto buffer_size = [&]() -> uint64_t {
			if (spec.fixed_size)
				return spec.fixed_size;
 
			if (spec.size_from_arg < 0 || spec.size_from_arg >= call.guest_args.size())
				return 0;
 
			return call.guest_args[spec.size_from_arg];
		};
 
		auto marshal_flat = [&](size_t size, bool copy_in, bool copy_out, bool relocate = false) -> bool {
			if (!guest_value)
				return false;
 
			if (size > MAX_MARSHALLED_BUFFER_SIZE)
				return false;
 
			if (!size)
				return call.local_args[index] = 0, true;
 
			void* local = call.allocate(size);
			if (!local || (copy_in && !read_guest(guest_value, local, size)))
				return false;
 
			call.local_args[index] = (uint64_t)local;
			if (copy_out)
				call.copy_backs.push_back({ guest_value, local, size, relocate });
 
			return true;
		};
 
		switch (spec.kind) {
			case arg_kind::scalar:
				return true;
			case arg_kind::handle_in: {
				if (!guest_value)
					return failure = STATUS_INVALID_HANDLE_VALUE, false;
 
				HANDLE local = nullptr;
				if (!resolve_input_handle(guest_value, call, local))
					return failure = STATUS_INVALID_HANDLE_VALUE, false;
 
				call.local_args[index] = (uint64_t)local;
				return true;
			}
			case arg_kind::handle_out: {
				if (!guest_value)
					return false;
 
				auto local = (HANDLE*)call.allocate(sizeof(HANDLE));
				if (!local)
					return false;
 
				call.local_args[index] = (uint64_t)local;
				call.output_handles.push_back({ guest_value, local });
				return true;
			}
			case arg_kind::buffer_in:
				return marshal_flat(buffer_size(), true, false);
			case arg_kind::buffer_out:
				return marshal_flat(buffer_size(), false, true, true);
			case arg_kind::buffer_inout:
				return marshal_flat(buffer_size(), true, true, true);
			case arg_kind::unicode_string_in: {
				if (!guest_value)
					return false;
 
				UNICODE_STRING* local = nullptr;
				if (!marshal_unicode_string(call, guest_value, local))
					return false;
 
				call.local_args[index] = (uint64_t)local;
				return true;
			}
			case arg_kind::object_attributes_in: {
				if (!guest_value)
					return false;
 
				OBJECT_ATTRIBUTES* local = nullptr;
				if (!marshal_object_attributes(call, guest_value, local))
					return false;
 
				call.local_args[index] = (uint64_t)local;
				return true;
			}
			case arg_kind::io_status_block_out:
				return marshal_flat(sizeof(IO_STATUS_BLOCK), false, true);
			case arg_kind::client_id_in:
				return marshal_flat(sizeof(CLIENT_ID), true, false);
			case arg_kind::large_integer_in:
				return marshal_flat(sizeof(LARGE_INTEGER), true, false);
			case arg_kind::u32_out:
				return marshal_flat(sizeof(uint32_t), false, true);
			case arg_kind::u64_out:
				return marshal_flat(sizeof(uint64_t), false, true);
			case arg_kind::u64_inout:
				return marshal_flat(sizeof(uint64_t), true, true);
			case arg_kind::handle_array_in: {
				if (!guest_value || spec.size_from_arg < 0)
					return false;
 
				const uint64_t count = call.guest_args[spec.size_from_arg];
				if (!count || count > 65536 || count > MAX_MARSHALLED_BUFFER_SIZE / sizeof(uint64_t))
					return false;
 
				std::vector<uint64_t> guest_handles(count);
				if (!read_guest(guest_value, guest_handles.data(), guest_handles.size() * sizeof(uint64_t)))
					return false;
 
				auto local_handles = (HANDLE*)call.allocate(guest_handles.size() * sizeof(HANDLE));
				if (!local_handles)
					return false;
 
				for (size_t i = 0; i < guest_handles.size(); ++i) {
					if (!resolve_input_handle(guest_handles[i], call, local_handles[i]))
						return failure = STATUS_INVALID_HANDLE_VALUE, false;
				}
 
				call.local_args[index] = (uint64_t)local_handles;
				return true;
			}
		}
 
		failure = STATUS_NOT_SUPPORTED_VALUE;
		return false;
	}
 
	static NTSTATUS invoke_native(void* function, const uint64_t* a, size_t count) {
		switch (count) {
			case 0: return ((NTSTATUS(NTAPI*)())(function))();
			case 1: return ((NTSTATUS(NTAPI*)(uint64_t))(function))(a[0]);
			case 2: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t))(function))(a[0], a[1]);
			case 3: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2]);
			case 4: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3]);
			case 5: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4]);
			case 6: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5]);
			case 7: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
			case 8: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
			case 9: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
			case 10: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);
			case 11: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10]);
			case 12: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11]);
			case 13: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12]);
			case 14: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13]);
			case 15: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14]);
			case 16: return ((NTSTATUS(NTAPI*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(function))(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
			default: return STATUS_NOT_SUPPORTED_VALUE;
		}
	}
 
	NTSTATUS invoke_as_target(void* function, const uint64_t* args, size_t count) {
		HANDLE previous_token = nullptr;
		const bool had_previous_token = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_IMPERSONATE, TRUE, &previous_token) != FALSE;
		bool impersonating = false;
		if (target_impersonation_token)
			impersonating = SetThreadToken(nullptr, target_impersonation_token) != FALSE;
 
		const NTSTATUS status = invoke_native(function, args, count);
 
		if (impersonating) {
			if (had_previous_token)
				SetThreadToken(nullptr, previous_token);
			else
				RevertToSelf();
		}
 
		if (previous_token)
			CloseHandle(previous_token);
 
		return status;
	}
 
	NTSTATUS dispatch_duplicate_object() {
		std::array<uint64_t, 7> args{};
		uint64_t rsp = 0;
		uc_reg_read(uc, UC_X86_REG_R10, &args[0]);
		uc_reg_read(uc, UC_X86_REG_RDX, &args[1]);
		uc_reg_read(uc, UC_X86_REG_R8, &args[2]);
		uc_reg_read(uc, UC_X86_REG_R9, &args[3]);
		uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
		for (size_t i = 4; i < args.size(); ++i) {
			if (!read_guest(rsp + 0x28 + (i - 4) * sizeof(uint64_t), &args[i], sizeof(uint64_t)))
				return STATUS_ACCESS_VIOLATION_VALUE;
		}
 
		marshalled_call call{};
		HANDLE source_process = nullptr;
		HANDLE target_process = nullptr;
		if (!resolve_input_handle(args[0], call, source_process) || !resolve_input_handle(args[2], call, target_process)) {
			for (HANDLE temporary : call.temporary_handles)
				CloseHandle(temporary);
 
			return STATUS_INVALID_HANDLE_VALUE;
		}
 
		HANDLE target_handle = nullptr;
		std::array<uint64_t, 7> local_args{
			(uint64_t)source_process, args[1], (uint64_t)target_process, args[3] ? (uint64_t)&target_handle : 0, args[4], args[5], args[6]
		};
 
		static void* function = GetProcAddress(local_ntdll, "NtDuplicateObject");
		NTSTATUS status = function ? invoke_as_target(function, local_args.data(), local_args.size()) : STATUS_NOT_IMPLEMENTED_VALUE;
		if (NT_SUCCESS(status) && args[3]) {
			const uint64_t guest_target_handle = (uint64_t)target_handle;
			if (!write_guest(args[3], &guest_target_handle, sizeof(guest_target_handle)))
				status = STATUS_ACCESS_VIOLATION_VALUE;
		}
 
		for (HANDLE temporary : call.temporary_handles)
			CloseHandle(temporary);
		return status;
	}
 
	NTSTATUS dispatch_syscall(uint32_t id) {
		auto trace_arguments = [&](const char* syscall_name, size_t argument_count) {
			argument_count = (std::min)(argument_count, MAX_NATIVE_ARGUMENTS);
			std::array<uint64_t, MAX_NATIVE_ARGUMENTS> arguments{};
			std::array<bool, MAX_NATIVE_ARGUMENTS> readable{};
 
			readable[0] = uc_reg_read(uc, UC_X86_REG_R10, &arguments[0]) == UC_ERR_OK;
			if (argument_count > 1)
				readable[1] = uc_reg_read(uc, UC_X86_REG_RDX, &arguments[1]) == UC_ERR_OK;
			if (argument_count > 2)
				readable[2] = uc_reg_read(uc, UC_X86_REG_R8, &arguments[2]) == UC_ERR_OK;
			if (argument_count > 3)
				readable[3] = uc_reg_read(uc, UC_X86_REG_R9, &arguments[3]) == UC_ERR_OK;
 
			if (argument_count > 4) {
				uint64_t rsp = 0;
				if (uc_reg_read(uc, UC_X86_REG_RSP, &rsp) == UC_ERR_OK) {
					for (size_t i = 4; i < argument_count; ++i) {
						const uint64_t address = rsp + 0x28 + (i - 4) * sizeof(uint64_t);
						readable[i] = read_guest(address, &arguments[i], sizeof(arguments[i]));
					}
				}
			}
 
			printf("syscall: %s (id=0x%x, argc=%zu)\n", syscall_name, id, argument_count);
			for (size_t i = 0; i < argument_count; ++i) {
				if (readable[i])
					printf("  arg[%zu] = 0x%016llx (%llu)\n", i, arguments[i], arguments[i]);
				else
					printf("  arg[%zu] = <unreadable>\n", i);
			}
 
			return arguments;
		};
 
		const auto name_it = syscall_names_by_id.find(id);
		if (name_it == syscall_names_by_id.end()) {
			trace_arguments("<unknown>", 4);
			const std::string key = "#" + std::to_string(id);
			if (reported_missing_syscalls.insert(key).second)
				printf("syscall: unknown target ID 0x%x has no argument descriptor, only register arguments were logged\n", id);
 
			return STATUS_NOT_IMPLEMENTED_VALUE;
		}
 
		const std::string& name = name_it->second;
		const auto descriptor_it = syscall_descriptors.find(name);
		size_t trace_argument_count = 4;
		if (name == "NtClose")
			trace_argument_count = 1;
		else if (name == "NtDuplicateObject")
			trace_argument_count = 7;
		else if (descriptor_it != syscall_descriptors.end())
			trace_argument_count = descriptor_it->second.args.size();
 
		const auto traced_arguments = trace_arguments(name.c_str(), trace_argument_count);
		if (name == "NtClose")
			return close_guest_handle(traced_arguments[0]);
		if (name == "NtDuplicateObject")
			return dispatch_duplicate_object();
 
		if (descriptor_it == syscall_descriptors.end()) {
			if (reported_missing_syscalls.insert(name).second)
				printf("syscall: %s (0x%x) has no descriptor\n", name.c_str(), id);
 
			return STATUS_NOT_IMPLEMENTED_VALUE;
		}
 
		const syscall_desc& desc = descriptor_it->second;
		if (desc.args.size() > MAX_NATIVE_ARGUMENTS)
			return STATUS_NOT_SUPPORTED_VALUE;
 
		marshalled_call call{};
		uint64_t rsp = 0;
		uc_reg_read(uc, UC_X86_REG_R10, &call.guest_args[0]);
		if (desc.args.size() > 1) uc_reg_read(uc, UC_X86_REG_RDX, &call.guest_args[1]);
		if (desc.args.size() > 2) uc_reg_read(uc, UC_X86_REG_R8, &call.guest_args[2]);
		if (desc.args.size() > 3) uc_reg_read(uc, UC_X86_REG_R9, &call.guest_args[3]);
		uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
 
		for (size_t i = 4; i < desc.args.size(); ++i) {
			const uint64_t address = rsp + 0x28 + (i - 4) * sizeof(uint64_t);
			if (!read_guest(address, &call.guest_args[i], sizeof(uint64_t)))
				return STATUS_ACCESS_VIOLATION_VALUE;
		}
 
		if (desc.apc_routine_arg >= 0 && call.guest_args[desc.apc_routine_arg])
			return STATUS_NOT_SUPPORTED_VALUE;
 
		NTSTATUS failure = STATUS_ACCESS_VIOLATION_VALUE;
		for (size_t i = 0; i < desc.args.size(); ++i) {
			if (!marshal_argument(call, i, desc.args[i], failure)) {
				for (HANDLE temporary : call.temporary_handles)
					CloseHandle(temporary);
 
				return failure;
			}
		}
 
		void* function = GetProcAddress(local_ntdll, name.c_str());
		if (!function) {
			for (HANDLE temporary : call.temporary_handles)
				CloseHandle(temporary);
 
			return STATUS_NOT_IMPLEMENTED_VALUE;
		}
 
		NTSTATUS status = invoke_as_target(function, call.local_args.data(), desc.args.size());
 
		if (status == STATUS_PENDING_VALUE && desc.complete_pending && desc.io_status_block_arg >= 0) {
			HANDLE wait_handle = nullptr;
			if (desc.wait_handle_arg >= 0)
				wait_handle = (HANDLE)call.local_args[desc.wait_handle_arg];
			if (!wait_handle && !call.local_args.empty())
				wait_handle = (HANDLE)call.local_args[0];
 
			using NtWaitForSingleObject_fn = NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
			static const auto wait = (NtWaitForSingleObject_fn)GetProcAddress(local_ntdll, "NtWaitForSingleObject");
			if (wait && wait_handle && NT_SUCCESS(wait(wait_handle, FALSE, nullptr))) {
				const auto* local_iosb = (const IO_STATUS_BLOCK*)call.local_args[desc.io_status_block_arg];
				if (local_iosb)
					status = local_iosb->Status;
			}
		}
 
		for (const auto& output : call.copy_backs) {
			if (output.relocate_internal_pointers && output.size >= sizeof(uint64_t)) {
				auto bytes = (uint8_t*)output.local_address;
				const uint64_t local_begin = (uint64_t)output.local_address;
				const uint64_t local_end = local_begin + output.size;
				for (size_t offset = 0; offset + sizeof(uint64_t) <= output.size; offset += sizeof(uint64_t)) {
					uint64_t value = 0;
					memcpy(&value, bytes + offset, sizeof(value));
					if (value >= local_begin && value < local_end) {
						value = output.guest_address + (value - local_begin);
						memcpy(bytes + offset, &value, sizeof(value));
					}
				}
			}
 
			if (!write_guest(output.guest_address, output.local_address, output.size))
				status = STATUS_ACCESS_VIOLATION_VALUE;
		}
 
		for (const auto& output : call.output_handles) {
			if (!NT_SUCCESS(status) || !*output.local_address) {
				if (*output.local_address)
					CloseHandle(*output.local_address);
 
				continue;
			}
 
			uint64_t guest_handle = 0;
			if (!publish_output_handle(*output.local_address, guest_handle)) {
				CloseHandle(*output.local_address);
				status = STATUS_UNSUCCESSFUL_VALUE;
				continue;
			}
 
			if (!write_guest(output.guest_address, &guest_handle, sizeof(guest_handle))) {
				close_guest_handle(guest_handle);
				status = STATUS_ACCESS_VIOLATION_VALUE;
			}
		}
 
		for (HANDLE temporary : call.temporary_handles)
			CloseHandle(temporary);
 
		refreshed_this_call.clear();
		return status;
	}
 
	bool map_code_page(uint64_t page_address) {
		page_address = page_align_down(page_address);
		if (is_private(page_address))
			return false;
 
		if (mapped.count(page_address)) {
			code_pages[page_address] = true;
			return true;
		}
 
		if (!sync_page_from_remote(page_address))
			return false;
 
		code_pages[page_address] = true;
		return true;
	}
 
	static bool hook_mem_invalid(uc_engine*, uc_mem_type type, uint64_t address, int, int64_t, void* user_data) {
		auto emu = (emulator*)user_data;
		if (emu->is_private(address)) {
			emu->hook_failed = true;
			return printf("error: private/guard memory fault at 0x%llx\n", address), false;
		}
 
		const uint64_t page = page_align_down(address);
		const bool ok = type == UC_MEM_FETCH_UNMAPPED ? emu->map_code_page(page) : emu->sync_page_from_remote(page);
		if (!ok)
			emu->hook_failed = true;
 
		if (ok && type != UC_MEM_FETCH_UNMAPPED)
			emu->refreshed_this_call[page] = true;
 
		return ok;
	}
 
	static void hook_mem_read(uc_engine* uc_engine, uc_mem_type, uint64_t address, int, int64_t, void* user_data) {
		auto emu = (emulator*)user_data;
		const uint64_t page = page_align_down(address);
		if (emu->is_private(address) || emu->code_pages.count(page) || emu->dirty_remote_pages.count(page) || !emu->mapped.count(page) || emu->refreshed_this_call.count(page))
			return;
 
		if (!emu->sync_page_from_remote(page)) {
			emu->hook_failed = true;
			uc_emu_stop(uc_engine);
			return;
		}
 
		emu->refreshed_this_call[page] = true;
	}
 
	static void hook_mem_write(uc_engine* uc_engine, uc_mem_type, uint64_t address, int size, int64_t value, void* user_data) {
		auto emu = (emulator*)user_data;
		if (emu->is_private(address))
			return;
 
		if (size <= 0) {
			emu->hook_failed = true;
			uc_emu_stop(uc_engine);
			return;
		}
 
		if (size <= sizeof(value)) {
			if (!emu->write_remote(address, &value, size)) {
				emu->hook_failed = true;
				uc_emu_stop(uc_engine);
			}
 
			return;
		}
 
		const uint64_t first = page_align_down(address);
		const uint64_t last = page_align_down(address + size - 1);
		for (uint64_t page = first; page <= last; page += PAGE_SIZE)
			emu->dirty_remote_pages.insert(page);
	}
 
	static void hook_syscall(uc_engine* uc_engine, void* user_data) {
		auto emu = (emulator*)user_data;
		uint64_t rax = 0;
		uc_reg_read(uc_engine, UC_X86_REG_RAX, &rax);
 
		if (!emu->flush_dirty_remote_pages()) {
			emu->hook_failed = true;
			uc_emu_stop(uc_engine);
			return;
		}
 
		const NTSTATUS status = emu->dispatch_syscall(rax);
		const uint64_t result = status;
		uc_reg_write(uc_engine, UC_X86_REG_RAX, &result);
	}
 
public:
	~emulator() {
		for (const auto& [guest, local] : emulated_handles) {
			(void)guest;
			if (local)
				CloseHandle(local);
		}
 
		if (uc) uc_close(uc);
		if (remote) CloseHandle(remote);
		if (remote_thread) CloseHandle(remote_thread);
		if (target_impersonation_token) CloseHandle(target_impersonation_token);
	}
 
	bool initialize(DWORD target_pid, DWORD target_tid = 0) {
		remote_pid = target_pid;
		remote = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE, FALSE, target_pid);
		if (!remote)
			return printf("error: OpenProcess %lu failed %lu\n", target_pid, GetLastError()), false;
 
		uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
		if (err != UC_ERR_OK)
			return printf("error: failed to initialize unicorn: %s\n", uc_strerror(err)), false;
 
		uc_hook invalid_hook = 0;
		uc_hook read_hook = 0;
		uc_hook write_hook = 0;
		uc_hook syscall_hook = 0;
		if (uc_hook_add(uc, &invalid_hook, UC_HOOK_MEM_UNMAPPED, hook_mem_invalid, this, 1, 0) != UC_ERR_OK ||
			uc_hook_add(uc, &read_hook, UC_HOOK_MEM_READ, hook_mem_read, this, 1, 0) != UC_ERR_OK ||
			uc_hook_add(uc, &write_hook, UC_HOOK_MEM_WRITE, hook_mem_write, this, 1, 0) != UC_ERR_OK ||
			uc_hook_add(uc, &syscall_hook, UC_HOOK_INSN, hook_syscall, this, 1, 0, UC_X86_INS_SYSCALL) != UC_ERR_OK)
			return printf("error: failed to install unicorn hooks\n"), false;
 
		if (!setup_stack() || !setup_environment(target_tid))
			return false;
 
		initialize_syscall_descriptors();
		if (!discover_syscalls())
			return false;
 
		printf("emulator initialized, attached to PID=%lu TID=%lu (%zu syscall descriptors)\n", remote_pid, emulated_tid, syscall_descriptors.size());
		return true;
	}
 
	struct call_result {
		bool ok = false;
		uint64_t rax = 0;
	};
 
	uintptr_t remote_syscall_address(const char* name) const {
		const auto it = syscall_addresses_by_name.find(name);
		return it == syscall_addresses_by_name.end() ? 0 : it->second;
	}
 
	template<typename type>
	static uint64_t to_u64(type value) {
		static_assert(sizeof(type) <= sizeof(uint64_t), "argument too large");
		static_assert(std::is_trivially_copyable_v<type>, "argument must be trivially copyable");
		uint64_t result = 0;
		memcpy(&result, &value, sizeof(type));
		return result;
	}
 
	template<typename... stack_args_t>
	call_result call_remote(uintptr_t function_address, uint64_t a1 = 0, uint64_t a2 = 0,
							uint64_t a3 = 0, uint64_t a4 = 0, stack_args_t... stack_args) {
		refreshed_this_call.clear();
		if (!refresh_dynamic_environment())
			return {};
 
		constexpr size_t stack_count = sizeof...(stack_args_t);
		uint64_t stack_values[stack_count > 0 ? stack_count : 1] = { to_u64(stack_args)... };
		if (!stack_base || !function_address)
			return {};
 
		uint64_t frame_size = 8 + 32;
		if (stack_count > ((std::numeric_limits<uint64_t>::max)() - frame_size) / 8)
			return {};
 
		frame_size += stack_count * 8;
		if (!align_up(frame_size, 16, frame_size) || frame_size + 8 >= STACK_SIZE)
			return printf("error: call frame is too large\n"), call_result{};
 
		const uint64_t rsp = stack_base - 8 - frame_size;
		if (!write_emulated(rsp, &return_sentinel, sizeof(return_sentinel)))
			return {};
 
		const uint64_t zero = 0;
		for (size_t i = 0; i < 4; ++i) {
			if (!write_emulated(rsp + 8 + i * 8, &zero, sizeof(zero)))
				return {};
		}
		for (size_t i = 0; i < stack_count; ++i) {
			if (!write_emulated(rsp + 40 + i * 8, &stack_values[i], sizeof(uint64_t)))
				return {};
		}
 
		if (uc_reg_write(uc, UC_X86_REG_RSP, &rsp) != UC_ERR_OK ||
			uc_reg_write(uc, UC_X86_REG_RCX, &a1) != UC_ERR_OK ||
			uc_reg_write(uc, UC_X86_REG_RDX, &a2) != UC_ERR_OK ||
			uc_reg_write(uc, UC_X86_REG_R8, &a3) != UC_ERR_OK ||
			uc_reg_write(uc, UC_X86_REG_R9, &a4) != UC_ERR_OK)
			return printf("error: failed to initialize call registers\n"), call_result{};
 
		if (!map_code_page(page_align_down(function_address)))
			return {};
 
		hook_failed = false;
		constexpr uint64_t timeout_microseconds = 5'000'000;
		constexpr size_t instruction_limit = 10'000'000;
		const uc_err err = uc_emu_start(uc, function_address, return_sentinel, 0, 0);
 
		if (!flush_dirty_remote_pages())
			hook_failed = true;
 
		uint64_t rax = 0;
		uc_reg_read(uc, UC_X86_REG_RAX, &rax);
		if (err != UC_ERR_OK || hook_failed)
			return printf("error: uc_emu_start failed: %s\n", uc_strerror(err)), call_result{ false, rax };
 
		uint64_t rip = 0;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);
		if (rip != return_sentinel)
			return printf("error: emulation stopped before the function returned (RIP=0x%llx)\n", rip), call_result{ false, rax };
 
		return { true, rax };
	}
};
