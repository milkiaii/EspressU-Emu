#pragma once

class StringBuf
{
public:
	StringBuf(uint32 bufferSize)
	{
		this->allocated = true;
		this->length = 0;
		// If the process is short of memory, settle for a smaller buffer (the output is cut off at the limit) instead of writing
		// through a null pointer. isValid() is false when nothing could be allocated.
		uint32 size = bufferSize;
		this->str = (uint8*)malloc((size_t)size + 4);
		while (!this->str && size > 64 * 1024)
		{
			size /= 2;
			this->str = (uint8*)malloc((size_t)size + 4);
		}
		this->limit = this->str ? size : 0;
		if (this->str)
			this->str[0] = '\0';
	}

	bool isValid() const
	{
		return this->str != nullptr;
	}

	~StringBuf()
	{
		if (this->allocated)
			free(this->str);
	}

	template<typename TFmt, typename ... TArgs>
	void addFmt(const TFmt& format, TArgs&&... args)
	{
		if (!this->str)
			return;
		auto r = fmt::vformat_to_n((char*)(this->str + this->length), (size_t)(this->limit - this->length), fmt::detail::to_string_view(format), fmt::make_format_args(args...));
		this->length += (uint32)r.size;
	}

	void add(const char* appendedStr)
	{
		if (!this->str)
			return;
		const char* outputStart = (char*)(this->str + this->length);
		char* output = (char*)outputStart;
		const char* outputEnd = (char*)(this->str + this->limit - 1);
		while (output < outputEnd)
		{
			char c = *appendedStr;
			if (c == '\0')
				break;
			*output = c;
			appendedStr++;
			output++;
		}
		this->length += (uint32)(output - outputStart);
		*output = '\0';
	}

	void add(std::string_view appendedStr)
	{
		if (!this->str)
			return;
		size_t copyLen = appendedStr.size();
		if (this->length + copyLen + 1 >= this->limit)
		{
			if (!_reserve(std::max<uint32>(this->length + copyLen + 64, this->limit + this->limit / 2)))
				return; // out of memory: drop the text, the buffer keeps what it has
		}
		char* outputStart = (char*)(this->str + this->length);
		std::copy(appendedStr.data(), appendedStr.data() + copyLen, outputStart);
		length += copyLen;
		outputStart[copyLen] = '\0';
	}

	void reset()
	{
		length = 0;
	}

	uint32 getLen() const
	{
		return length;
	}

	const char* c_str() const
	{
		if (!str)
			return "";
		str[length] = '\0';
		return (const char*)str;
	}

	void shrink_to_fit()
	{
		if (!this->allocated)
			return;
		if (!this->str)
			return;
		uint32 newLimit = this->length;
		uint8* resized = (uint8*)realloc(this->str, newLimit + 4);
		if (!resized)
			return; // keep the bigger buffer
		this->str = resized;
		this->limit = newLimit;
	}

private:
	bool _reserve(uint32 newLimit)
	{
		cemu_assert_debug(newLimit > length);
		uint8* resized = (uint8*)realloc(this->str, (size_t)newLimit + 4);
		if (!resized)
			return false; // the old buffer is still valid
		this->str = resized;
		this->limit = newLimit;
		return true;
	}

	uint8*	str;
	uint32	length;
	uint32	limit;
	bool	allocated;
};