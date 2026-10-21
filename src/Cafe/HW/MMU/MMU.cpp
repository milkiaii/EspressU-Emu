#include "Cafe/HW/MMU/MMU.h"
#include "Cafe/GraphicPack/GraphicPack2.h"
#include "Cemu/Logging/CemuLogging.h"
#include "WindowSystem.h"
#include "util/MemMapper/MemMapper.h"
#include "config/ActiveSettings.h"
#include <algorithm>
#include <vector>
#if BOOST_OS_IOS
#include "util/MemMapper/SparseReservation.h"
#endif

uint8* memory_base = NULL;
uint8* memory_elfCodeArena = NULL;

#if BOOST_OS_IOS
static MemMapper::SparseReservation s_sparseReservation;
static bool s_usingSparseReservation = false;
static uintptr_t s_failedSparseAddress = 0;
static size_t s_failedSparseSize = 0;

static void memory_releaseSparseRange(uintptr_t address, size_t size)
{
	MemMapper::FreeReservation(reinterpret_cast<void*>(address), size);
}

static bool memory_reserveSparseRange(uintptr_t base, uint64_t offset, uint64_t size)
{
	return s_sparseReservation.Ensure(base, offset, size, MemMapper::GetPageSize(),
		[](uintptr_t address, size_t length) {
			if (MemMapper::ReserveMemory(reinterpret_cast<void*>(address), length,
				MemMapper::PAGE_PERMISSION::P_NONE) == reinterpret_cast<void*>(address))
				return true;
			s_failedSparseAddress = address;
			s_failedSparseSize = length;
			return false;
		}, memory_releaseSparseRange);
}
#endif


// ---------------------------------------------------------------------------------------------
// Page-table mode (iOS only)
//
// Fallback for devices that cannot hand out the contiguous 4 GiB guest reservation. Only the guest ranges that exist are
// reserved, and guest accesses go through g_memoryPageTable (see MMUTranslate.h) instead of memory_base + address.
// ---------------------------------------------------------------------------------------------
extern std::vector<MMURange*> g_mmuRanges; // defined further down

uint8** g_memoryPageTable = nullptr;
MMUTranslate::Arena g_memoryArenas[MMUTranslate::MAX_ARENAS];
uint32 g_memoryArenaCount = 0;
uint8* g_memoryFaultGranule = nullptr;

#if CEMU_MMU_PAGETABLE_SUPPORTED
static std::vector<uint8*> s_pageTableStorage; // forward table storage (one entry per guest page)
static std::vector<std::vector<uint32>> s_pageTableReverse; // reverse table storage, one per arena

namespace
{
	struct PageTableSegment
	{
		uint64 begin;
		uint64 end;
	};

	// The guest ranges that need to be backed, rounded to host granules. Optional ranges (the 448 MiB overlay arena) are skipped:
	// address space is the scarce resource on these devices. With mergeAdjacent, ranges that touch each other end up in one
	// segment so that an access that straddles them still hits contiguous host memory.
	std::vector<PageTableSegment> memory_computePageTableSegments(bool mergeAdjacent)
	{
		using namespace MMUTranslate;
		std::vector<PageTableSegment> intervals;
		auto addInterval = [&](uint64 begin, uint64 end)
		{
			begin &= ~(uint64)PAGE_MASK;
			end = (end + PAGE_MASK) & ~(uint64)PAGE_MASK;
			if (end > begin)
				intervals.push_back({begin, end});
		};
		for (MMURange* range : g_mmuRanges)
		{
			if (range->isOptional())
				continue;
			addInterval(range->getBase(), (uint64)range->getBase() + range->getInitSize());
		}
		addInterval(0x00800000, 0x01000000); // HBL ELF code arena, see memory_enableHBLELFCodeArea()
		std::sort(intervals.begin(), intervals.end(), [](const PageTableSegment& a, const PageTableSegment& b) { return a.begin < b.begin; });
		std::vector<PageTableSegment> segments;
		for (const auto& itr : intervals)
		{
			if (!segments.empty() && (mergeAdjacent ? itr.begin <= segments.back().end : itr.begin < segments.back().end))
				segments.back().end = std::max(segments.back().end, itr.end);
			else
				segments.push_back(itr);
		}
		return segments;
	}
}

static std::string memory_formatPageTableArenaLayout(const std::vector<std::vector<size_t>>& groups, const std::vector<PageTableSegment>& segments)
{
	std::string text;
	for (const auto& group : groups)
	{
		uint64 total = 0;
		for (size_t i : group)
			total += (segments[i].end - segments[i].begin) + MMUTranslate::PAGE_SIZE;
		text += fmt::format("{}x{}MiB ", group.size(), total >> 20);
	}
	return text;
}

// Reserves the host arenas for one grouping of segments and builds the tables. Returns false (and reserves nothing) if an arena cannot be reserved.
static bool memory_tryBuildPageTable(const std::vector<PageTableSegment>& segments, std::vector<std::vector<size_t>> groups)
{
	using namespace MMUTranslate;
	if (groups.size() > MAX_ARENAS)
		return false;
	auto groupSize = [&](const std::vector<size_t>& g)
	{
		size_t total = 0;
		for (size_t i : g)
			total += (size_t)(segments[i].end - segments[i].begin) + PAGE_SIZE; // segment + guard granule
		return total;
	};
	// biggest arena first: it is the most likely to fail, and reverse lookups find the large arenas first
	std::sort(groups.begin(), groups.end(), [&](const auto& a, const auto& b) { return groupSize(a) > groupSize(b); });

	std::vector<uint8*> bases;
	std::vector<size_t> sizes;
	auto releaseAll = [&]()
	{
		for (size_t g = 0; g < bases.size(); g++)
			MemMapper::FreeReservation(bases[g], sizes[g]);
		bases.clear();
		sizes.clear();
	};
	for (size_t g = 0; g < groups.size(); g++)
	{
		const size_t arenaSize = groupSize(groups[g]);
		uint8* base = (uint8*)MemMapper::ReserveMemory(nullptr, arenaSize, MemMapper::PAGE_PERMISSION::P_NONE);
		if (!base)
		{
			cemuLog_log(LogType::Force, "Page-table mode: unable to reserve a {} MiB arena (layout {})", arenaSize >> 20, memory_formatPageTableArenaLayout(groups, segments));
			releaseAll();
			return false;
		}
		bases.push_back(base);
		sizes.push_back(arenaSize);
	}
	uint8* faultGranule = (uint8*)MemMapper::ReserveMemory(nullptr, PAGE_SIZE, MemMapper::PAGE_PERMISSION::P_NONE);
	if (!faultGranule)
	{
		cemuLog_log(LogType::Force, "Page-table mode: unable to reserve the {} KiB fault granule", PAGE_SIZE >> 10);
		releaseAll();
		return false;
	}

	s_pageTableStorage.assign(NUM_PAGES, faultGranule); // every guest page that is not backed faults
	s_pageTableReverse.assign(groups.size(), {});
	for (size_t g = 0; g < groups.size(); g++)
	{
		s_pageTableReverse[g].assign(sizes[g] >> PAGE_SHIFT, REVERSE_UNMAPPED);
		std::vector<size_t> members = groups[g];
		std::sort(members.begin(), members.end()); // keep guest order inside an arena
		size_t hostOffset = 0;
		for (size_t segIndex : members)
		{
			const PageTableSegment& seg = segments[segIndex];
			const uint32 firstPage = (uint32)(seg.begin >> PAGE_SHIFT);
			const uint32 pageCount = (uint32)((seg.end - seg.begin) >> PAGE_SHIFT);
			const size_t hostPage = hostOffset >> PAGE_SHIFT;
			for (uint32 p = 0; p < pageCount; p++)
			{
				s_pageTableStorage[firstPage + p] = bases[g] + hostOffset + ((size_t)p << PAGE_SHIFT);
				s_pageTableReverse[g][hostPage + p] = firstPage + p;
			}
			// guard granule: maps back to the guest page right behind the segment (wraps to 0 for a segment that ends at 4 GiB)
			s_pageTableReverse[g][hostPage + pageCount] = (uint32)(seg.end >> PAGE_SHIFT);
			hostOffset += (size_t)(seg.end - seg.begin) + PAGE_SIZE;
		}
		g_memoryArenas[g] = {bases[g], sizes[g], s_pageTableReverse[g].data()};
	}
	size_t totalSize = 0;
	for (size_t sz : sizes)
		totalSize += sz;
	g_memoryFaultGranule = faultGranule;
	g_memoryArenaCount = (uint32)groups.size();
	memory_base = (uint8*)POISON_BASE;
	g_memoryPageTable = s_pageTableStorage.data(); // enables page-table mode, keep last
	cemuLog_log(LogType::Force, "Guest memory mode: page-table ({} segments in {} arena(s), {} MiB reserved, first arena at {:#x}; layout {})",
		segments.size(), groups.size(), totalSize >> 20, (uintptr_t)bases[0], memory_formatPageTableArenaLayout(groups, segments));
	return true;
}

static bool memory_buildPageTable()
{
	using namespace MMUTranslate;
	if (MemMapper::GetPageSize() > PAGE_SIZE)
	{
		cemuLog_log(LogType::Force, "Page-table mode: host page size {} is larger than the {} byte guest page granule", MemMapper::GetPageSize(), PAGE_SIZE);
		return false;
	}
	// First choice keeps touching guest ranges contiguous on the host. If no layout can be reserved, the last resort only merges
	// ranges that overlap: a guest access that straddles two touching ranges would then fault, but the emulator can start.
	for (int pass = 0; pass < 2; pass++)
	{
		const bool mergeAdjacent = (pass == 0);
		const std::vector<PageTableSegment> segments = memory_computePageTableSegments(mergeAdjacent);
		if (!mergeAdjacent)
			cemuLog_log(LogType::Force, "Page-table mode: retrying with adjacent guest ranges in separate host blocks (accesses straddling two ranges will fault)");
		std::vector<size_t> order(segments.size()); // segment indices, biggest first
		for (size_t i = 0; i < order.size(); i++)
			order[i] = i;
		std::sort(order.begin(), order.end(), [&](size_t a, size_t b) { return (segments[a].end - segments[a].begin) > (segments[b].end - segments[b].begin); });

		// 1) one arena, 2) the biggest segment alone and the rest together, 3) every segment in its own arena
		std::vector<std::vector<std::vector<size_t>>> layouts;
		layouts.push_back({order});
		if (order.size() > 1)
			layouts.push_back({std::vector<size_t>(order.begin() + 1, order.end()), {order[0]}});
		{
			std::vector<std::vector<size_t>> perSegment;
			for (size_t i : order)
				perSegment.push_back({i});
			layouts.push_back(std::move(perSegment));
		}
		for (auto& layout : layouts)
		{
			if (memory_tryBuildPageTable(segments, layout))
				return true;
		}
	}
	return false;
}

bool memory_isGuestRangeReserved(uint32 address, uint32 size)
{
	if (!memory_isPageTableMode())
		return true;
	using namespace MMUTranslate;
	if (size == 0)
		return true;
	const uint64 beginPage = address >> PAGE_SHIFT;
	const uint64 endPage = (((uint64)address + size - 1) >> PAGE_SHIFT) + 1;
	if (endPage > NUM_PAGES)
		return false;
	uint8* previous = nullptr;
	for (uint64 p = beginPage; p < endPage; p++)
	{
		uint8* host = g_memoryPageTable[p];
		if (host == g_memoryFaultGranule)
			return false; // not backed
		if (previous && host != previous + PAGE_SIZE)
			return false; // not contiguous on the host
		previous = host;
	}
	return true;
}
#else
bool memory_isGuestRangeReserved(uint32, uint32)
{
	return true;
}
#endif

// Logs how much address space this process can still reserve (largest free block, total reservable)
void memory_logFreeAddressSpace(const char* label)
{
#if BOOST_OS_IOS
	const MemMapper::FreeAddressSpaceInfo info = MemMapper::ProbeFreeAddressSpace();
	std::string blocks;
	for (const auto& block : info.blocks)
		blocks += fmt::format("{}x{}MiB ", block.second, block.first >> 20);
	cemuLog_log(LogType::Force, "Address space ({}): largest free block {} MiB, total reservable {} MiB (probe capped at 8 GiB) [{}]", label, info.largestBlockBytes >> 20, info.totalBytes >> 20, blocks);
#else
	(void)label;
#endif
}

static void* memory_commitRange(uint32 offset, uint32 size)
{
#if CEMU_MMU_PAGETABLE_SUPPORTED
	if (memory_isPageTableMode())
	{
		using namespace MMUTranslate;
		const uint64 begin = offset & ~(uint64)PAGE_MASK;
		const uint64 end = ((uint64)offset + size + PAGE_MASK) & ~(uint64)PAGE_MASK;
		if (!memory_isGuestRangeReserved((uint32)begin, (uint32)(end - begin)))
		{
			cemuLog_log(LogType::Force, "Page-table mode: guest range {:08x}-{:08x} is not backed by reserved host memory", offset, (uint64)offset + size);
			return nullptr;
		}
		if (!MemMapper::AllocateMemory(memory_translate((uint32)begin), (size_t)(end - begin), MemMapper::PAGE_PERMISSION::P_RW, true))
			return nullptr;
		return memory_translate(offset);
	}
#endif
#if BOOST_OS_IOS
	if (s_usingSparseReservation && !memory_reserveSparseRange(reinterpret_cast<uintptr_t>(memory_base), offset, size))
	{
		cemuLog_log(LogType::Force, "Sparse reservation failed: host {:#x}, size {:#x}", s_failedSparseAddress, s_failedSparseSize);
		return nullptr;
	}
#endif
	return MemMapper::AllocateMemory(memory_base + offset, size, MemMapper::PAGE_PERMISSION::P_RW, true);
}

void checkMemAlloc(void* result)
{
	if (result == nullptr)
		assert_dbg();
}

void memory_initPhysicalLayout()
{
	assert_dbg();

}

std::vector<struct MMURange*> g_mmuRanges;

std::vector<MMURange*> memory_getMMURanges()
{
	return g_mmuRanges;
}

MMURange* memory_getMMURangeByAddress(MPTR address)
{
	for (auto& itr : g_mmuRanges)
	{
		if (address >= itr->getBase() && address < itr->getEnd())
			return itr;
	}
	return nullptr;
}

MMURange::MMURange(const uint32 baseAddress, const uint32 size, MMU_MEM_AREA_ID areaId, const std::string_view name, MFLAG flags) : baseAddress(baseAddress), size(size), initSize(size), areaId(areaId), name(name), flags(flags)
{
	g_mmuRanges.emplace_back(this);
}

void MMURange::mapMem()
{
	cemu_assert_debug(!m_isMapped);
	if (memory_commitRange(baseAddress, size) == nullptr)
	{
		std::string errorMsg = _tr("Unable to allocate {} memory", name);
		WindowSystem::ShowErrorDialog(errorMsg, _tr("Error"));
		#if BOOST_OS_WINDOWS
		ExitProcess(-1);
		#else
		exit(-1);
		#endif
	}
	m_isMapped = true;
}

static std::mutex s_gpuMappingMutex;
static std::vector<std::pair<MPTR, uint32>> s_gpuMappings;
static size_t s_keptRangeCount = 0;

void memory_registerGpuMapping(MPTR baseAddress, uint32 size)
{
	std::lock_guard<std::mutex> lock(s_gpuMappingMutex);
	s_gpuMappings.emplace_back(baseAddress, size);
}

void memory_unregisterGpuMapping(MPTR baseAddress, uint32 size)
{
	std::lock_guard<std::mutex> lock(s_gpuMappingMutex);
	auto it = std::find(s_gpuMappings.begin(), s_gpuMappings.end(), std::make_pair(baseAddress, size));
	if (it != s_gpuMappings.end())
		s_gpuMappings.erase(it);
}

bool memory_isRangeGpuMapped(MPTR baseAddress, uint32 size)
{
	std::lock_guard<std::mutex> lock(s_gpuMappingMutex);
	for (auto& m : s_gpuMappings)
	{
		if ((uint64)baseAddress < (uint64)m.first + m.second && (uint64)m.first < (uint64)baseAddress + size)
			return true;
	}
	return false;
}

size_t memory_getKeptRangeCount()
{
	return s_keptRangeCount;
}

void MMURange::unmapMem()
{
	// page-table mode works on whole host granules, linear mode keeps passing the exact size
	uint8* hostPtr = memory_translate(baseAddress);
	size_t hostSize = size;
	if (memory_isPageTableMode())
	{
		const uint64 begin = baseAddress & ~(uint64)MMUTranslate::PAGE_MASK;
		const uint64 end = ((uint64)baseAddress + size + MMUTranslate::PAGE_MASK) & ~(uint64)MMUTranslate::PAGE_MASK;
		hostPtr = memory_translate((uint32)begin);
		hostSize = (size_t)(end - begin);
	}
	if (memory_isRangeGpuMapped(baseAddress, size))
	{
		MemMapper::FreeMemoryKeepPages(hostPtr, hostSize);
		s_keptRangeCount++;
		cemuLog_log(LogType::Force, "clean slate: kept {} pages (GPU mapping still alive)", name);
	}
	else
	{
		const auto start = std::chrono::steady_clock::now();
		MemMapper::FreeMemory(hostPtr, hostSize, true);
		const auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
		cemuLog_log(LogType::Force, "Guest memory: replaced {} ({} MiB) with fresh pages in {}.{} ms", name, size / (1024 * 1024), us / 1000, (us % 1000) / 100);
	}
	m_isMapped = false;
}

MMURange mmuRange_LOW0					{ 0x00010000, 0x000F0000, MMU_MEM_AREA_ID::CODE_LOW0, "CODE_LOW0" };
MMURange mmuRange_TRAMPOLINE_AREA		{ 0x00E00000, 0x00200000, MMU_MEM_AREA_ID::CODE_TRAMPOLINE, "TRAMPOLINE_AREA" };
MMURange mmuRange_CODECAVE				{ 0x01800000, 0x00400000, MMU_MEM_AREA_ID::CODE_CAVE, "CODECAVE" };
MMURange mmuRange_TEXT_AREA				{ 0x02000000, 0x0C000000, MMU_MEM_AREA_ID::CODE_MAIN, "TEXT_AREA" };
MMURange mmuRange_CEMU_AREA				{ 0x0E000000, 0x02000000, MMU_MEM_AREA_ID::CEMU_PRIVATE, "CEMU_AREA", MMURange::MFLAG::FLAG_MAP_EARLY };
MMURange mmuRange_MEM2					{ 0x10000000, 0x40000000, MMU_MEM_AREA_ID::MEM2_DATA, "MEM2" };
MMURange mmuRange_OVERLAY_AREA			{ 0xA0000000, 0x1C000000, MMU_MEM_AREA_ID::OVERLAY, "OVERLAY_AREA", MMURange::MFLAG::FLAG_OPTIONAL };
MMURange mmuRange_FGBUCKET				{ 0xE0000000, 0x04000000, MMU_MEM_AREA_ID::FGBUCKET, "FGBUCKET" };
MMURange mmuRange_TILINGAPERTURE		{ 0xE8000000, 0x02000000, MMU_MEM_AREA_ID::TILING_APERATURE, "TILINGAPERTURE" };
MMURange mmuRange_MEM1					{ 0xF4000000, 0x02000000, MMU_MEM_AREA_ID::MEM1, "MEM1" };
MMURange mmuRange_RPLLOADER				{ 0xF6000000, 0x02000000, MMU_MEM_AREA_ID::RPLLOADER, "RPLLOADER_AREA" };
MMURange mmuRange_SHARED_AREA			{ 0xF8000000, 0x02000000, MMU_MEM_AREA_ID::SHAREDDATA, "SHARED_AREA", MMURange::MFLAG::FLAG_MAP_EARLY };
MMURange mmuRange_CORE0_LC				{ 0xFFC00000, 0x00005000, MMU_MEM_AREA_ID::CPU_LC0, "CORE0_LC" };
MMURange mmuRange_CORE1_LC				{ 0xFFC40000, 0x00005000, MMU_MEM_AREA_ID::CPU_LC1, "CORE1_LC" };
MMURange mmuRange_CORE2_LC				{ 0xFFC80000, 0x00005000, MMU_MEM_AREA_ID::CPU_LC2, "CORE2_LC" };
MMURange mmuRange_HIGHMEM				{ 0xFFFFF000, 0x00001000, MMU_MEM_AREA_ID::CPU_PER_CORE, "PER-CORE" };

void memory_init()
{
	memory_logFreeAddressSpace("before guest memory reservation");
	if (!memory_base)
	{
		memory_base = (uint8*)MemMapper::ReserveMemory(nullptr, size_t{0x100000000ULL}, MemMapper::PAGE_PERMISSION::P_RW);
		if (memory_base)
			cemuLog_log(LogType::Force, "Guest memory mode: linear (4 GiB reservation at {:#x})", (uintptr_t)memory_base);
	}
#if BOOST_OS_IOS
	if (!memory_base)
	{
		cemuLog_log(LogType::Force, "Contiguous guest reservation failed; trying sparse reservations (host page size: {})", MemMapper::GetPageSize());

		for (uintptr_t base = 0x10000000ULL; base < 0x1000000000ULL; base += 0x10000000ULL)
		{
			bool success = true;
			for (auto* range : g_mmuRanges)
			{
				if (!memory_reserveSparseRange(base, range->getBase(), range->getSize()))
				{
					success = false;
					break;
				}
			}

			if (success)
				success = memory_reserveSparseRange(base, 0x00800000, 0x00800000);
			if (success)
			{
				memory_base = reinterpret_cast<uint8*>(base);
				s_usingSparseReservation = true;
				cemuLog_log(LogType::Force, "Using sparse iOS guest memory reservations");
				cemuLog_log(LogType::Force, "Guest memory mode: linear, sparse reservations at {:#x}", (uintptr_t)memory_base);
				break;
			}
			s_sparseReservation.ReleaseAll(base, memory_releaseSparseRange);
		}
		if (!memory_base)
			cemuLog_log(LogType::Force, "Sparse guest reservation failed: last host address {:#x}, size {:#x}", s_failedSparseAddress, s_failedSparseSize);
	}
#endif
#if CEMU_MMU_PAGETABLE_SUPPORTED
	if (!memory_base)
	{
		// neither the contiguous 4 GiB reservation nor the sparse one worked: back only the guest ranges that exist and translate through a page table
		cemuLog_log(LogType::Force, "Guest memory: the 4 GiB reservation failed, falling back to page-table mode");
		memory_buildPageTable();
	}
#endif
	if( !memory_base )
	{
		memory_logFreeAddressSpace("guest memory reservation failed");
		debug_printf("memory_init(): Unable to reserve guest memory regions\n");
		debugBreakpoint();
		WindowSystem::ShowErrorDialog(_tr("Unable to reserve guest memory regions"), _tr("Error"));
		exit(-1);
	}
	memory_logFreeAddressSpace("after guest memory reservation");
	for (auto& itr : g_mmuRanges)
	{
		if (itr->isMappedEarly())
			itr->mapMem();
	}
}

void memory_mapForCurrentTitle()
{
	for (auto& itr : g_mmuRanges)
		if(!itr->isMapped())
			itr->resetConfig();
	auto gfxPackMappings = GraphicPack2::GetActiveRAMMappings();
	for (auto& mapping : gfxPackMappings)
	{
		MMURange* mmuRange = nullptr;
		for (auto& itr : g_mmuRanges)
		{
			if (itr->getBase() == mapping.first)
			{
				mmuRange = itr;
				break;
			}
		}
		if (!mmuRange)
		{
			cemuLog_log(LogType::Force, fmt::format("Graphic pack error: Unable to apply modified RAM mapping {:08x}-{:08x}. Start address must match one of the existing MMU ranges:", mapping.first, mapping.second));
			for (auto& itr : g_mmuRanges)
			{
				if(itr->isMapped())
					continue;
				cemuLog_log(LogType::Force, fmt::format("{:08x}-{:08x} ({:})", itr->getBase(), itr->getEnd(), itr->getName()));
			}
			continue;
		}
		bool isOverlapping = false;
		for (auto& itr : g_mmuRanges)
		{
			if(itr == mmuRange)
				continue;
			if (mapping.first < itr->getEnd() && mapping.second > itr->getBase())
			{
				cemuLog_log(LogType::Force, fmt::format("Graphic pack error: Unable to apply modified memory range {:08x}-{:08x} since it is overlapping with {:08x}-{:08x} ({:})", mapping.first, mapping.second, itr->getBase(), itr->getEnd(), itr->getName()));
				isOverlapping = true;
			}
		}
		if(isOverlapping)
			continue;
		if (!memory_isGuestRangeReserved(mapping.first, mapping.second - mapping.first))
		{
			cemuLog_log(LogType::Force, fmt::format("Graphic pack: Unable to apply modified RAM mapping {:08x}-{:08x} in page-table mode (range exceeds the reserved guest memory)", mapping.first, mapping.second));
			continue;
		}
		mmuRange->setEnd(mapping.second);
	}

	for (auto& itr : g_mmuRanges)
	{
		if (!itr->isOptional() && !itr->isMappedEarly())
			itr->mapMem();
	}
}

void memory_unmapForCurrentTitle()
{
	s_keptRangeCount = 0;
    for (auto& itr : g_mmuRanges)
    {
        if (itr->isMapped() && !itr->isMappedEarly())
            itr->unmapMem();
    }
}

void memory_logModifiedMemoryRanges()
{
	auto gfxPackMappings = GraphicPack2::GetActiveRAMMappings();
	for (auto& mapping : gfxPackMappings)
	{
		MMURange* mmuRange = nullptr;
		for (auto& itr : g_mmuRanges)
		{
			if (itr->getBase() == mapping.first)
			{
				mmuRange = itr;
				break;
			}
		}
		if (!mmuRange)
			continue;
		sint32 extraMem = (sint32)mapping.second - (sint32)(mmuRange->getBase() + mmuRange->getInitSize());
		extraMem = (extraMem + 1023) / 1024;
		std::string memAmountStr;
		if (extraMem >= 8 * 1024 * 1024)
			memAmountStr = fmt::format("{:+}MiB", (extraMem + 1023) / 1024);
		else
			memAmountStr = fmt::format("{:+}KiB", extraMem);
		cemuLog_log(LogType::Force, fmt::format("Graphic pack: Using modified RAM mapping {:08x}-{:08x} ({})", mapping.first, mapping.second, memAmountStr));
	}
}

void memory_enableOverlayArena()
{
	if (mmuRange_OVERLAY_AREA.isMapped())
		return;
	if (!memory_isGuestRangeReserved(mmuRange_OVERLAY_AREA.getBase(), mmuRange_OVERLAY_AREA.getSize()))
	{
		// page-table mode does not reserve the optional overlay range
		cemuLog_log(LogType::Force, "Overlay arena is not available in page-table mode");
		return;
	}
	mmuRange_OVERLAY_AREA.mapMem();
}

void memory_enableHBLELFCodeArea()
{
	if (memory_elfCodeArena != NULL)
		return;
	memory_elfCodeArena = (uint8*)memory_commitRange(0x00800000, 0x00800000);
	if (memory_elfCodeArena == NULL)
	{
		debug_printf("memory_enableHBLELFCodeArea(): Unable to allocate memory for ELF arena\n");
		debugBreakpoint();
	}
}

bool memory_isAddressRangeAccessible(MPTR virtualAddress, uint32 size)
{
	for (auto& itr : g_mmuRanges)
	{
		if(!itr->isMapped())
			continue;
		if (virtualAddress >= itr->getBase() && virtualAddress < itr->getEnd())
		{
			uint32 remainingSize = itr->getEnd() - virtualAddress;
			return size <= remainingSize && itr->isMapped();
		}
	}
	return false;
}

uint32 memory_virtualToPhysical(uint32 virtualOffset)
{
	return virtualOffset;
}

uint32 memory_physicalToVirtual(uint32 physicalOffset)
{
	return physicalOffset;
}

uint8* memory_getPointerFromPhysicalOffset(uint32 physicalOffset)
{
	return memory_translate(physicalOffset);
}

uint32 memory_getVirtualOffsetFromPointer(void* ptr)
{
	if( !ptr )
		return MPTR_NULL;
	return memory_reverseTranslate(ptr);
}

uint8* memory_getPointerFromVirtualOffset(uint32 virtualOffset)
{
	return memory_translate(virtualOffset);
}

uint8* memory_getPointerFromVirtualOffsetAllowNull(uint32 virtualOffset)
{
	if( virtualOffset == MPTR_NULL )
		return nullptr;
	return memory_getPointerFromVirtualOffset(virtualOffset);
}

void memory_writeDouble(uint32 address, double vf)
{
	uint64 v = *(uint64*)&vf;
	uint32 v1 = v&0xFFFFFFFF;
	uint32 v2 = v>>32;
	uint8* ptr = memory_getPointerFromVirtualOffset(address);
	*(uint32*)(ptr+4) = CPU_swapEndianU32(v1);
	*(uint32*)(ptr+0) = CPU_swapEndianU32(v2);
}

void memory_writeFloat(uint32 address, float vf)
{
	uint32 v = *(uint32*)&vf;
	*(uint32*)(memory_getPointerFromVirtualOffset(address)) = CPU_swapEndianU32(v);
}

void memory_writeU32(uint32 address, uint32 v)
{
	*(uint32*)(memory_getPointerFromVirtualOffset(address)) = CPU_swapEndianU32(v);
}

void memory_writeU64(uint32 address, uint64 v)
{
	*(uint64*)(memory_getPointerFromVirtualOffset(address)) = CPU_swapEndianU64(v);
}

void memory_writeU16(uint32 address, uint16 v)
{
	*(uint16*)(memory_getPointerFromVirtualOffset(address)) = CPU_swapEndianU16(v);
}

void memory_writeU8(uint32 address, uint8 v)
{
	*(uint8*)(memory_getPointerFromVirtualOffset(address)) = v;
}

double memory_readDouble(uint32 address)
{
	uint32 v[2];
	v[1] = *(uint32*)(memory_getPointerFromVirtualOffset(address));
	v[0] = *(uint32*)(memory_getPointerFromVirtualOffset(address)+4);
	v[0] = CPU_swapEndianU32(v[0]);
	v[1] = CPU_swapEndianU32(v[1]);
	return *(double*)v;
}

float memory_readFloat(uint32 address)
{
	uint32 v = *(uint32*)(memory_getPointerFromVirtualOffset(address));
	v = CPU_swapEndianU32(v);
	return *(float*)&v;
}

uint64 memory_readU64(uint32 address)
{
	uint64 v = *(uint64*)(memory_getPointerFromVirtualOffset(address));
	return CPU_swapEndianU64(v);
}

uint32 memory_readU32(uint32 address)
{
	uint32 v = *(uint32*)(memory_getPointerFromVirtualOffset(address));
	return CPU_swapEndianU32(v);
}

uint16 memory_readU16(uint32 address)
{
	uint16 v = *(uint16*)(memory_getPointerFromVirtualOffset(address));
	return CPU_swapEndianU16(v);
}

uint8 memory_readU8(uint32 address)
{
	return *(uint8*)(memory_getPointerFromVirtualOffset(address));
}

uint32 memory_getContiguousReadableBytes(uint32 virtualAddress)
{
    uint32 maxBytes = 0;

    for (auto& r : g_mmuRanges)
    {
        if (!r->isMapped())
            continue;

        if (virtualAddress >= r->getBase() && virtualAddress < r->getEnd())
        {
            uint32 remaining = r->getEnd() - virtualAddress;
            return remaining;
        }
    }

    return 0;
}

extern "C" DLLEXPORT void* memory_getBase()
{
	return memory_base;
}

void memory_writeDumpFile(uint32 startAddr, uint32 size, const fs::path& path)
{
	fs::path filePath = path;
	filePath /= fmt::format("{:08x}.bin", startAddr);
	FileStream* fs = FileStream::createFile2(filePath);
	if (fs)
	{
		fs->writeData(memory_translate(startAddr), size);
		delete fs;
	}
}

void memory_createDump()
{
	const uint32 pageSize = MemMapper::GetPageSize();
	fs::path path = ActiveSettings::GetUserDataPath("dump/ramDump{:}", (uint32)time(nullptr));
	fs::create_directories(path);

	for (auto& itr : g_mmuRanges)
	{
		if(!itr->isMapped())
			continue;
		memory_writeDumpFile(itr->getBase(), itr->getSize(), path);
	}
}

namespace MMU
{

	std::unordered_map<PAddr, MMIOFuncWrite32>* g_mmioHandlerW32{};
	std::unordered_map<PAddr, MMIOFuncWrite16>* g_mmioHandlerW16{};
	std::unordered_map<PAddr, MMIOFuncRead32>* g_mmioHandlerR32{};
	std::unordered_map<PAddr, MMIOFuncRead16>* g_mmioHandlerR16{};

	void _initHandlers()
	{
		if (g_mmioHandlerW32)
			return;
		g_mmioHandlerW32 = new std::unordered_map<PAddr, MMIOFuncWrite32>();
		g_mmioHandlerW16 = new std::unordered_map<PAddr, MMIOFuncWrite16>();
		g_mmioHandlerR32 = new std::unordered_map<PAddr, MMIOFuncRead32>();
		g_mmioHandlerR16 = new std::unordered_map<PAddr, MMIOFuncRead16>();
	}

	PAddr _MakeMMIOAddress(MMIOInterface interfaceLocation, uint32 relativeAddress)
	{
		PAddr addr = 0;
		if (interfaceLocation == MMIOInterface::INTERFACE_0C000000)
			addr = 0x0C000000;
		else if (interfaceLocation == MMIOInterface::INTERFACE_0D000000)
			addr = 0x0D000000;
		else
			assert_dbg();
		return addr + relativeAddress;
	}

	void RegisterMMIO_W32(MMIOInterface interfaceLocation, uint32 relativeAddress, MMIOFuncWrite32 ptr)
	{
		_initHandlers();
		g_mmioHandlerW32->emplace(_MakeMMIOAddress(interfaceLocation, relativeAddress), ptr);
	}

	void RegisterMMIO_W16(MMIOInterface interfaceLocation, uint32 relativeAddress, MMIOFuncWrite16 ptr)
	{
		_initHandlers();
		g_mmioHandlerW16->emplace(_MakeMMIOAddress(interfaceLocation, relativeAddress), ptr);
	}

	void RegisterMMIO_R32(MMIOInterface interfaceLocation, uint32 relativeAddress, MMIOFuncRead32 ptr)
	{
		_initHandlers();
		PAddr addr = _MakeMMIOAddress(interfaceLocation, relativeAddress);
		g_mmioHandlerR32->emplace(addr, ptr);
	}

	void RegisterMMIO_R16(MMIOInterface interfaceLocation, uint32 relativeAddress, MMIOFuncRead16 ptr)
	{
		_initHandlers();
		g_mmioHandlerR16->emplace(_MakeMMIOAddress(interfaceLocation, relativeAddress), ptr);
	}

	void WriteMMIO_32(PAddr address, uint32 value)
	{
		cemu_assert_debug((address & 0x3) == 0);
		auto itr = g_mmioHandlerW32->find(address);
		if (itr == g_mmioHandlerW32->end())
		{
			return;
		}
		return itr->second(address, value);
	}

	void WriteMMIO_16(PAddr address, uint16 value)
	{
		cemu_assert_debug((address & 0x1) == 0);
		auto itr = g_mmioHandlerW16->find(address);
		if (itr == g_mmioHandlerW16->end())
		{
			return;
		}
		return itr->second(address, value);
	}

	uint32 ReadMMIO_32(PAddr address)
	{
		cemu_assert_debug((address & 0x3) == 0);
		auto itr = g_mmioHandlerR32->find(address);
		if(itr == g_mmioHandlerR32->end())
		{
			return 0;
		}
		return itr->second(address);
	}

	uint16 ReadMMIO_16(PAddr address)
	{
		cemu_assert_debug((address & 0x1) == 0);
		auto itr = g_mmioHandlerR16->find(address);
		if (itr == g_mmioHandlerR16->end())
		{
			return 0;
		}
		return itr->second(address);
	}

}
