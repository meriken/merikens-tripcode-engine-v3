#include "MerikensTripcodeEngine.h"



spinlock::spinlock()
{
	flag.clear();
}

void spinlock::lock()
{
	while (flag.test_and_set(std::memory_order_acquire))
		std::this_thread::yield();
}

void spinlock::unlock()
{
	flag.clear(std::memory_order_release);
}

#if defined(_WIN32)

namespace mte {
	named_event::named_event() : native_event_handle(NULL)
	{
	}

	named_event::~named_event()
	{
		if (native_event_handle)
			CloseHandle(native_event_handle);
	}

	bool named_event::is_open()
	{
		return (native_event_handle != NULL && native_event_handle != INVALID_HANDLE_VALUE);
	}

	bool named_event::open_or_create(const char *arg_name)
	{
		if (is_open())
			return false;
		data_name = arg_name;
		std::wstring_convert<std::codecvt_byname<wchar_t, char, std::mbstate_t>> converter(new std::codecvt_byname<wchar_t, char, std::mbstate_t>("cp" + std::to_string(GetACP())));
		native_event_handle = OpenEventW(EVENT_ALL_ACCESS, false, converter.from_bytes(arg_name).data());
		return is_open();
	}

	void named_event::wait()
	{
		if (is_open())
			WaitForSingleObject(native_event_handle, INFINITE);
	}

	bool named_event::poll()
	{
		return is_open() && WaitForSingleObject(native_event_handle, 0) == WAIT_OBJECT_0;
	}

	std::string named_event::name()
	{
		return data_name;
	}
}

#else

namespace mte {
	named_event::named_event()
	{
	}

	named_event::~named_event()
	{
	}

	bool named_event::is_open()
	{
		return false;
	}

	bool named_event::open_or_create(const char *arg_name)
	{
		return false;
	}

	void named_event::wait()
	{
	}

	bool named_event::poll()
	{
		return false;
	}

	std::string named_event::name()
	{
		return data_name;
	}
}

#endif

#ifdef ENABLE_AVX

#if defined(_MSC_VER) || defined (__INTEL_COMPILER)

#include <stdint.h>
#include <intrin.h>

void run_cpuid(uint32_t eax, uint32_t ecx, int32_t *abcd)
{
	__cpuidex(abcd, eax, ecx);
}

#elif defined(__GNUC__) || defined(__clang__)

void run_cpuid(uint32_t eax, uint32_t ecx, int32_t *abcd)
{
	int a, b, c, d;
	__asm("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(eax), "c"(ecx) : );
	abcd[0] = a;
	abcd[1] = b;
	abcd[2] = c;
	abcd[3] = d;
}

static uint64_t __xgetbv(uint32_t xcr)
{
	uint32_t eax, edx;

	__asm__ volatile ("xgetbv" : "=a" (eax), "=d" (edx) : "c" (xcr));
	return (static_cast<uint64_t>(edx) << 32) | eax;
}

#endif

int32_t check_xcr0_ymm()
{
	uint32_t xcr0;
	xcr0 = (uint32_t)__xgetbv(0);
	return ((xcr0 & 6) == 6); /* checking if xmm and ymm state are enabled in XCR0 */
}

int32_t check_4th_gen_intel_core_features()
{
	int32_t abcd[4];
	uint32_t fma_movbe_osxsave_mask = ((1 << 12) | (1 << 22) | (1 << 27));
	uint32_t avx2_bmi12_mask = (1 << 5) | (1 << 3) | (1 << 8);

	/* CPUID.(EAX=01H, ECX=0H):ECX.FMA[bit 12]==1   &&
	CPUID.(EAX=01H, ECX=0H):ECX.MOVBE[bit 22]==1 &&
	CPUID.(EAX=01H, ECX=0H):ECX.OSXSAVE[bit 27]==1 */
	run_cpuid(1, 0, abcd);
	if ((abcd[2] & fma_movbe_osxsave_mask) != fma_movbe_osxsave_mask)
		return 0;

	if (!check_xcr0_ymm())
		return 0;

	/*  CPUID.(EAX=07H, ECX=0H):EBX.AVX2[bit 5]==1  &&
	CPUID.(EAX=07H, ECX=0H):EBX.BMI1[bit 3]==1  &&
	CPUID.(EAX=07H, ECX=0H):EBX.BMI2[bit 8]==1  */
	run_cpuid(7, 0, abcd);
	if ((abcd[1] & avx2_bmi12_mask) != avx2_bmi12_mask)
		return 0;

	/* CPUID.(EAX=80000001H):ECX.LZCNT[bit 5]==1 */
	run_cpuid(0x80000001, 0, abcd);
	if ((abcd[2] & (1 << 5)) == 0)
		return 0;

	return 1;
}

bool IsAVX2Supported()
{
	static int32_t the_4th_gen_features_available = -1;
	/* test is performed once */
	if (the_4th_gen_features_available < 0)
		the_4th_gen_features_available = check_4th_gen_intel_core_features();

	return the_4th_gen_features_available;
}

bool IsAVXSupported()
{
	int32_t abcd[4];

	run_cpuid(1, 0, abcd);
	return ((abcd[2] & 0x18000000) == 0x18000000);
}

#endif
