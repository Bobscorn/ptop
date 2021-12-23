#pragma once

#include <vector>
#include <memory>
#include <string>
#include <cstring>

#ifndef PRINT_LINE
#define PRINT_LINE std::runtime_error(std::string(__func__) + "(" + std::to_string(__LINE__) + ")")
#define PRINT_MSG_LINE(x) std::runtime_error(std::string(__func__) + "(" + std::to_string(__LINE__) + ") " + x)
#endif


// Example Message Data: 
// MESSAGE_TYPE | MESSAGE_LENGTH | MESSAGE_DATA
// A Message will always be sizeof(MESSAGE_TYPE) + sizeof(MESSAGE_LENGTH) + MESSAGE_LENGTH bytes long

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

typedef unsigned long MESSAGE_LENGTH_T;

struct Message
{
	MESSAGE_TYPE Type;
	MESSAGE_LENGTH_T Length;
	std::vector<char> Data;

	std::vector<char> to_bytes() const;
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
Message create_message(MESSAGE_TYPE type, T other_data)
{
	MESSAGE_LENGTH_T length = sizeof(other_data);
	Message mess;
	mess.Type = type;
	mess.Length = sizeof(other_data);
	mess.Data = std::vector<char>(&other_data, &other_data + sizeof(other_data));
	return mess;
}

inline Message create_message(MESSAGE_TYPE type)
{
	Message data;
	data.Type = type;
	data.Length = 0;
	data.Data = std::vector<char>();
	return data;
}

inline Message create_message(MESSAGE_TYPE type, std::vector<char> data)
{
	Message mess;
	mess.Type = type;
	mess.Length = data.size();
	mess.Data = std::move(data);
	return mess;
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
inline Message create_message(MESSAGE_TYPE type, Types... args)
{
	Message mess;
	mess.Data = std::vector<char>{};
	mess.Data.resize(sizeof(type));
	std::memcpy(mess.Data.data(), &type, sizeof(type));
	copy_to_message_struct::copy_to_message(mess.Data, args...);
	mess.Length = mess.Data.size();
	return mess;
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

inline Message create_message(MESSAGE_TYPE type, std::string data)
{
	Message mess;
	mess.Type = type;
	mess.Length = data.length();
	size_t len = data.length();
	mess.Data = std::vector<char>(sizeof(len), '0');
	std::memcpy(mess.Data.data(), &len, sizeof(len));
	mess.Data.reserve(sizeof(type) + sizeof(len) + data.length());
	mess.Data.insert(mess.Data.end(), data.begin(), data.end());
	return mess;
}
