#pragma once

#include <vector>
#include <memory>
#include <string>
#include <cstring>

#ifndef SHITTY_DEFINE
#define SHITTY_DEFINE(x) std::runtime_error(std::string(__func__) + "(" + std::to_string(__LINE__) + "): " + x)
#endif

enum class MESSAGE_TYPE
{
	NONE = 0,
	MSG,
	FILE,
	SET_NAME,
	CONNECT_PEER,
	READY_FOR_P2P,
	MY_DATA,
	AUTH_PLS,
	HERES_YOUR_AUTH,
};

inline std::string mt_to_string(const MESSAGE_TYPE& t)
{
	switch (t)
	{
	case MESSAGE_TYPE::MSG:
		return "MSG: Plain Text Msg";
	case MESSAGE_TYPE::FILE:
		return "FILE: Incoming File";
	case MESSAGE_TYPE::SET_NAME:
		return "SET_NAME: Request to change name alias";
	case MESSAGE_TYPE::CONNECT_PEER:
		return "CONNECT_PEER: Data required to connect to a peer";
	case MESSAGE_TYPE::READY_FOR_P2P:
		return "READY_FOR_P2P: Connection is ready for P2P";
	case MESSAGE_TYPE::MY_DATA:
		return "MY_DATA: Connection's Private :3 Data";
	case MESSAGE_TYPE::AUTH_PLS:
		return "AUTH_PLS: Request for Auth";
	case MESSAGE_TYPE::HERES_YOUR_AUTH:
		return "HERES_YOUR_AUTH: Auth Request Response";
	case MESSAGE_TYPE::NONE:
	default:
		return "NONE: None";
	}
}

template<class T, typename = std::enable_if_t<std::is_pod<T>::value>>
std::vector<char> create_message(MESSAGE_TYPE type, T other_data)
{
	std::vector<char> out(sizeof(type) + sizeof(other_data), '0');
	std::memcpy(out.data(), &type, sizeof(type));
	std::memcpy(out.data() + sizeof(type), &other_data, sizeof(other_data));
	return out;
}

inline std::vector<char> create_message(MESSAGE_TYPE type)
{
	std::vector<char> out(sizeof(type), '0');
	std::memcpy(out.data(), &type, sizeof(type));
	return out;
}

inline std::vector<char> create_message(MESSAGE_TYPE type, std::vector<char> data)
{
	data.insert(data.begin(), sizeof(type), '0');
	std::memcpy(data.data(), &type, sizeof(type));
	return data;
}

inline std::vector<char> create_message(MESSAGE_TYPE type, std::vector<char> data, std::vector<char> dataB)
{
	data.insert(data.begin(), sizeof(type), '0');
	std::memcpy(data.data(), &type, sizeof(type));
	data.insert(data.end(), dataB.begin(), dataB.end());
	return data;
}

struct copy_to_message_struct
{
	template<class... Types>
	static void copy_to_message(std::vector<char>& dst, Types... args);

	static void copy_to_message(std::vector<char>& dst);
};

template<class T, class... Types>
struct copy_to_message_template
{
	constexpr static void copy(std::vector<char>& dst, const T& arg, Types... other_args)
	{
		static_assert(std::is_pod<T>::value || std::is_same<std::vector<char>, T>::value, "Can only use POD or std::vector<char> in create_message");
		T* back = ((T*)&dst.back()) + 1;
		dst.resize(dst.size() + sizeof(T));
		*back = arg;
		copy_to_message_struct::copy_to_message(dst, other_args...);
	}
};

template<>
struct copy_to_message_template<std::vector<char>>
{
	static void copy(std::vector<char>& dst, const std::vector<char>& src)
	{
		dst.insert(dst.end(), src.begin(), src.end());
	}
};

template<class... Types>
struct copy_to_message_template<std::vector<char>, Types...>
{
	static void copy(std::vector<char>& dst, const std::vector<char>& src, Types... other_args)
	{
		dst.insert(dst.end(), src.begin(), src.end());
		copy_to_message_struct::copy_to_message(dst, other_args...);
	}
};

template<class ...Types>
inline void copy_to_message_struct::copy_to_message(std::vector<char>& dst, Types ...args)
{
	copy_to_message_template<Types...>::copy(dst, args...);
}

inline void copy_to_message_struct::copy_to_message(std::vector<char>& dst) {}

template<typename... Types>
inline std::vector<char> create_message(MESSAGE_TYPE type, Types... args)
{
	std::vector<char> data{};
	data.resize(sizeof(type));
	std::memcpy(data.data(), &type, sizeof(type));
	copy_to_message_struct::copy_to_message(data, args...);
	return data;
}

//template<>
//struct copy_to_message_template<std::vector<char>>
//{
//	static void copy(std::vector<char>& dst, const std::vector<char>& src)
//	{
//		dst.insert(dst.end(), src.begin(), src.end());
//	}
//};

//template<class T, typename = std::enable_if_t<std::is_pod<T>::value>, class... Types>
//inline void copy_to_message(std::vector<char>& dst, T arg, Types... other_args)
//{
//	T* back = (T*)&dst.back();
//	dst.resize(dst.size() + sizeof(T));
//	*back = arg;
//	copy_to_message(other_args...);
//}
//
//template<class... Types>
//inline void copy_to_message<std::vector<char>, Types...>(std::vector<char>& dst, const std::vector<char>& arg, Types... other_args)
//{
//	dst.insert(dst.end(), arg.begin(), arg.end());
//	copy_to_message(other_args...);
//}

inline std::vector<char> create_message(MESSAGE_TYPE type, std::string data)
{
	size_t len = data.length();
	std::vector<char> out_data(sizeof(type) + sizeof(len), '0');
	std::memcpy(out_data.data(), &type, sizeof(type));
	std::memcpy(out_data.data() + sizeof(type), &len, sizeof(len));
	out_data.reserve(sizeof(type) + sizeof(len) + data.length());
	out_data.insert(out_data.end(), data.begin(), data.end());
	return out_data;
}
