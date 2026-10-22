#pragma once

// Guest <-> host address translation for the emulated Wii U address space.
//
// Linear mode (default, every platform):
//     host = memory_base + guest
//   Needs one contiguous 4 GiB host reservation.
//
// Page-table mode (iOS only, fallback when the 4 GiB reservation cannot be made):
//     host = g_memoryPageTable[guest >> PAGE_SHIFT] + (guest & PAGE_MASK)
//   Only the guest ranges that exist are backed. Guest ranges that touch each other are merged into
//   one segment, and a segment is always one contiguous block of host memory, so an access that
//   straddles a page boundary (or two adjacent ranges) still hits contiguous host memory. Segments
//   live in one or more host arenas. A PROT_NONE guard granule follows every segment so a
//   one-past-the-end host pointer still maps back to the guest address one past the end.
//   Guest pages that are not backed point at a PROT_NONE fault granule, so a stray access faults
//   like it does in linear mode.

#if BOOST_OS_IOS
#define CEMU_MMU_PAGETABLE_SUPPORTED 1
#else
#define CEMU_MMU_PAGETABLE_SUPPORTED 0
#endif

// linear mode: origin of the guest address space.
// page-table mode: an address that is unmapped on purpose (see MMUTranslate::POISON_BASE). Guest addresses must never be added to it.
extern uint8* memory_base;

namespace MMUTranslate
{
	constexpr uint32 PAGE_SHIFT = 14; // 16 KiB, the iOS arm64 host page size. Must stay >= the host page size.
	constexpr uint32 PAGE_SIZE = 1u << PAGE_SHIFT;
	constexpr uint32 PAGE_MASK = PAGE_SIZE - 1;
	constexpr uint32 NUM_PAGES = 1u << (32 - PAGE_SHIFT);
	constexpr uint32 REVERSE_UNMAPPED = 0xFFFFFFFFu;
	constexpr uint32 MAX_ARENAS = 16;
	// Far outside the user address space of iOS (which is below 2^39). If some code still does memory_base + guestAddress in
	// page-table mode, it faults at once on an obviously invalid address instead of silently touching random memory.
	constexpr uintptr_t POISON_BASE = 0x0000700000000000ull;

	struct Arena
	{
		uint8* base;
		size_t size; // includes the trailing guard granule
		const uint32* reverse; // guest page index for every host page of this arena (REVERSE_UNMAPPED for padding)
	};
}

// Forward table, one host pointer per guest page. nullptr in linear mode.
extern uint8** g_memoryPageTable;
// Host reservations behind the guest address space in page-table mode (one, or several when the address space is fragmented).
extern MMUTranslate::Arena g_memoryArenas[MMUTranslate::MAX_ARENAS];
extern uint32 g_memoryArenaCount;
// PROT_NONE granule that every unbacked guest page points at
extern uint8* g_memoryFaultGranule;

inline bool memory_isPageTableMode()
{
#if CEMU_MMU_PAGETABLE_SUPPORTED
	return g_memoryPageTable != nullptr;
#else
	return false;
#endif
}

// guest address -> host pointer
inline uint8* memory_translate(uint32 guestAddress)
{
#if CEMU_MMU_PAGETABLE_SUPPORTED
	if (g_memoryPageTable != nullptr) [[unlikely]]
		return g_memoryPageTable[guestAddress >> MMUTranslate::PAGE_SHIFT] + (guestAddress & MMUTranslate::PAGE_MASK);
#endif
	return memory_base + guestAddress;
}

// host pointer -> guest address. Returns 0 for pointers outside of the backed guest memory in page-table mode.
inline uint32 memory_reverseTranslate(const void* hostPtr)
{
#if CEMU_MMU_PAGETABLE_SUPPORTED
	if (g_memoryPageTable != nullptr) [[unlikely]]
	{
		const uint8* p = (const uint8*)hostPtr;
		for (uint32 i = 0; i < g_memoryArenaCount; i++)
		{
			// the unsigned compare also rejects p < base. size includes the guard granule, so one-past-the-end is accepted
			const size_t offset = (size_t)(p - g_memoryArenas[i].base);
			if (offset >= g_memoryArenas[i].size)
				continue;
			const uint32 guestPage = g_memoryArenas[i].reverse[offset >> MMUTranslate::PAGE_SHIFT];
			if (guestPage == MMUTranslate::REVERSE_UNMAPPED)
				return 0;
			return (guestPage << MMUTranslate::PAGE_SHIFT) | (uint32)(offset & MMUTranslate::PAGE_MASK);
		}
		return 0;
	}
#endif
	return (uint32)((uintptr_t)hostPtr - (uintptr_t)memory_base);
}

// true if the host pointer lies inside the host memory that backs the guest address space
inline bool memory_isHostPtrInGuestSpace(const void* hostPtr)
{
	const uint8* p = (const uint8*)hostPtr;
#if CEMU_MMU_PAGETABLE_SUPPORTED
	if (g_memoryPageTable != nullptr) [[unlikely]]
	{
		for (uint32 i = 0; i < g_memoryArenaCount; i++)
		{
			if ((size_t)(p - g_memoryArenas[i].base) < g_memoryArenas[i].size)
				return true;
		}
		return false;
	}
#endif
	return p >= memory_base && p < (memory_base + 0x100000000ULL);
}
