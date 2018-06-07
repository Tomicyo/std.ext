#pragma once
#ifndef __STRING_PIECE_HPP_20180607__
#define __STRING_PIECE_HPP_20180607__

#include <string>

namespace std
{
	template <typename T>
	class base_string_piece
	{
	public:
		typedef size_t size_type;
		typedef typename T::value_type value_type;
		typedef const value_type* const_iterator;

		constexpr base_string_piece() : m_ptr(nullptr), m_length(0) {}
		constexpr base_string_piece(const value_type* str) : m_ptr(str), m_length(char_traits<value_type>::length(str)) {}
		constexpr base_string_piece(const value_type* offset, size_type len) : m_ptr(offset), m_length(len) {}
		base_string_piece(const typename T::const_iterator& begin, const typename T::const_iterator& end)
		{
			m_length = distance(begin, end);
			m_ptr = m_length > 0 ? &*begin : nullptr;
		}

		bool is_null() const { return m_ptr == nullptr; }
		constexpr const value_type* data() const { return m_ptr; }
		constexpr size_type size() const { return m_length; }
		constexpr size_type length() const { return m_length; }

		const_iterator begin() const { return m_ptr; }
		const_iterator end() const { return m_ptr + m_length; }

		T to_string() const { return is_null() ? T() : T(data(), size()); }
		explicit operator T() const { return to_string(); }

	private:
		const value_type* m_ptr;
		size_type m_length;
	};

	typedef base_string_piece<string> string_piece;
}

#endif