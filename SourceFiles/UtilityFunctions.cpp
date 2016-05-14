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

#if defined(_WIN32) || defined(__CYGWIN__)

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