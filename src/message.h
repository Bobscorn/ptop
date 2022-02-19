#pragma once

#include <vector>
#include <memory>
#include <string>
#include <cstring>
#include <stdexcept>



enum class ConnectionStatus
{
	PENDING = 0,
	SUCCESS = 1,
	FAILED = 2,
};


//uint32_t crc_data(const std::vector<char>& data);

// Example Message Data: 
// MESSAGE_TYPE | MESSAGE_LENGTH | MESSAGE_DATA
// A Message will always be sizeof(MESSAGE_TYPE) + sizeof(MESSAGE_LENGTH) + MESSAGE_LENGTH bytes long
constexpr int KILOBYTE = 1024;
constexpr int MEGABYTE = KILOBYTE * 1024;

enum class MESSAGE_TYPE
{
	NONE = 0,
	MY_DATA,
	READY_FOR_P2P,
	CONNECT_TO_PEER,
	PEER_MSG,
	PEER_FILE,
	UDP_SYN,
	UDP_SYN_ACK,
	UDP_ACK,
	MISSING_CHUNK,
	PEER_FILE_END,
	PEER_FILE_END_ACK,
	STREAM_ACKNOWLEDGED,
	STREAM_CHUNK,
	CHUNK_ERROR
};

typedef uint32_t MESSAGE_LENGTH_T;

struct Message
{
	MESSAGE_TYPE Type;
	MESSAGE_LENGTH_T Length;
	std::vector<char> Data;

	std::vector<char> to_bytes() const;

	inline bool operator==(const Message& other) const { return Type == other.Type && Length == other.Length && Data == other.Data; }

	template<class T>
	T read_type(int& read_index) const
	{
		int size = sizeof(T);
		if (read_index + size > Data.size())
			throw std::runtime_error("Not enough data to read");

		T* ptr = (T*)&(Data[read_index]);
		read_index += size;
		return *ptr;
	}

	

	static const Message null_message;
};

inline bool message_is_type(const MESSAGE_TYPE& type, const Message& m) { return m.Type == type; }
std::vector<Message> data_to_messages(const std::vector<char>& data);
template<>
inline std::string Message::read_type<std::string>(int& read_index) const
{
	int size = sizeof(size_t);
	if (read_index + size > Data.size())
		throw std::runtime_error("Not enough data to read string length");

	size_t len = read_type<size_t>(read_index);
	if (read_index + len * sizeof(char) > Data.size())
		throw std::runtime_error("Not enough data to read string characters");

	read_index += (int)len;
	return std::string(Data.data() + read_index - len, Data.data() + read_index);
}

struct StreamMessage : Message {
	//uint32_t chunk_crc;
};

template<class T>
struct to_message;

template<>
struct to_message<MESSAGE_TYPE>
{
	Message operator()(const MESSAGE_TYPE& t)
	{
		Message mess;
		mess.Data = std::vector<char>();
		mess.Length = 0;
		mess.Type = t;
		return mess;
	}
};

template<class T>
struct from_message;

template<class T>
struct from_message_with_crc;

inline std::string mt_to_string(const MESSAGE_TYPE& t)
{
	switch (t)
	{
		case MESSAGE_TYPE::MY_DATA:				return  "MY_DATA: Connection's Private :3 Data";
		case MESSAGE_TYPE::READY_FOR_P2P:		return  "READY_FOR_P2P: Connection is ready for P2P";
		case MESSAGE_TYPE::PEER_MSG:			return  "MSG: Plain Text Msg";
		case MESSAGE_TYPE::PEER_FILE:			return  "FILE: Incoming File";
		case MESSAGE_TYPE::CONNECT_TO_PEER:		return  "CONNECT_PEER: Data required to connect to a peer";
		case MESSAGE_TYPE::UDP_SYN:				return  "UDP_SYN: UDP Handshake initial message";
		case MESSAGE_TYPE::UDP_SYN_ACK:			return  "UDP_SYN_ACK: UDP Handshake response message";
		case MESSAGE_TYPE::UDP_ACK:				return  "UDP_ACK: UDP Handshake final response";
		case MESSAGE_TYPE::PEER_FILE_END:		return  "PEER_FILE_END: File end message";
		case MESSAGE_TYPE::PEER_FILE_END_ACK:	return  "PEER_FILE_END_ACK: File end message acknowledgement";
		case MESSAGE_TYPE::STREAM_ACKNOWLEDGED: return  "STREAM_ACKNOWLEDGED: File sending acknowledgement";
		case MESSAGE_TYPE::STREAM_CHUNK:		return  "STREAM_CHUNK: A chunk of a file";
		case MESSAGE_TYPE::CHUNK_ERROR:			return  "CHUNK_ERROR: An erroneous chunk message";

		case MESSAGE_TYPE::NONE:
		default:
			return "NONE: None";
	}
}

StreamMessage create_streammessage(MESSAGE_TYPE input_type, std::vector<char> data);

struct copy_to_message_struct
{
	template<class... Types>
	static void copy_to_message(std::vector<char>& dst, Types... args);

	static void copy_to_message(std::vector<char>& dst);
};

template<class T, class... Types>
struct copy_to_message_template
{
	template<typename = std::enable_if_t<std::is_pod<T>::value>>
	constexpr static void copy(std::vector<char>& destination, const T& arg, Types... other_args)
	{
		static_assert(std::is_pod<T>::value || std::is_same<std::vector<char>, T>::value, "Can only use POD or std::vector<char> in create_message");
		destination.resize(destination.size() + sizeof(T));
		T* back = ((T*)(&destination.back() - sizeof(T) + 1));
		*back = arg;
		copy_to_message_struct::copy_to_message(destination, other_args...);
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
	static void copy(std::vector<char>& destination, const std::vector<char>& src, Types... other_args)
	{
		destination.insert(destination.end(), src.begin(), src.end());
		copy_to_message_struct::copy_to_message(destination, other_args...);
	}
};

template<class... Types>
struct copy_to_message_template<std::string, Types...>
{
	static void copy(std::vector<char>& destination, const std::string& src, Types... other_args)
	{
		size_t cur_size = destination.size();
		size_t str_len = src.length();
		destination.resize(cur_size + sizeof(size_t));
		std::memcpy(&destination[cur_size], &str_len, sizeof(str_len));
		destination.reserve(destination.size() + str_len);
		destination.insert(destination.end(), src.begin(), src.end());
		copy_to_message_struct::copy_to_message(destination, other_args...);
	}
};

template<class ...Types>
inline void copy_to_message_struct::copy_to_message(std::vector<char>& destination, Types ...args)
{
	copy_to_message_template<Types...>::copy(destination, args...);
}

inline void copy_to_message_struct::copy_to_message(std::vector<char>& destination) {}

template<typename... Types>
inline Message create_message(MESSAGE_TYPE type, Types... args)
{
	Message mess;
	mess.Type = type;
	mess.Data = std::vector<char>{};
	copy_to_message_struct::copy_to_message(mess.Data, args...);
	mess.Length = (MESSAGE_LENGTH_T)mess.Data.size();
	return mess;
}
