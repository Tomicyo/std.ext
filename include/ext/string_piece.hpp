#pragma once
#ifndef __STRING_PIECE_HPP_20180607__
#define __STRING_PIECE_HPP_20180607__

#include <string>

namespace std
{
	namespace ext
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
			base_string_piece(const_iterator begin, const_iterator end)
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

			const value_type operator[](size_type index) const { return m_ptr[index]; }
			const value_type& operator[](size_type index) { return m_ptr[index]; }

			T to_string() const { return is_null() ? T() : T(data(), size()); }
			explicit operator T() const { return to_string(); }

            bool operator==(base_string_piece const& rhs)
            {
                if (m_length != rhs.m_length)
                    return false;
                if (m_ptr == rhs.m_ptr)
                    return true;
                return !char_traits<value_type>::compare(m_ptr, rhs.m_ptr, m_length * sizeof(value_type));
            }

		private:
			const value_type* m_ptr;
			size_type m_length;
		};

		typedef base_string_piece<string> string_piece;

	}
}

#endif