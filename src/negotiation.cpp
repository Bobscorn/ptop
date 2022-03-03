#include "negotiation.h"

#include <thread>
#include <math.h>
#include <cstring>

using namespace std::chrono;

const s_duration NEGOTIATION_PERIOD = 5s;
const s_duration NEGOTIATION_ACK_TIMEOUT = 5s;
const s_duration NEGOTIATION_TIMEOUT = 10s; 

auto create_blank_status()
{
	NegotiationStatus blank{};
	std::memset(&blank, 0, sizeof(NegotiationStatus));
	return blank;
}

const NegotiationStatus NegotiationStatus::BLANK_STATE = create_blank_status();

bool is_already_negotiation_status(NegotiationState state)
{
	return state != NegotiationState::NOT_NEGOTIATING && state != NegotiationState::NEGOTIATED_AS_SENDER && state != NegotiationState::NEGOTIATED_AS_RECEIVER;
}

void begin_negotiation(IDataSocketWrapper& socket, NegotiationStatus& status, float bandwidth, int num_packets, int packet_size)
{
	if (is_already_negotiation_status(status.state))
	{
		std::cout << "Can not begin negotiation, we are currently: " << ns_to_str(status.state) << std::endl;
		return;
	}

	status = NegotiationStatus::BLANK_STATE;

	if (num_packets <= 0)
		num_packets = 200;

	if (packet_size <= 0)
		packet_size = 8 * KILOBYTE;

	if (bandwidth <= 0.f)
		bandwidth = 0.f;

	std::cout << "Beginning negotiation with: " << bandwidth << "KB/s " << num_packets << " packets and " << packet_size << " byte packets" << std::endl;

	auto& begin = status.send_params;
	begin.num_packets = num_packets;
	begin.packet_byte_size = packet_size;
	begin.send_speed = bandwidth;

	std::this_thread::sleep_for(0.5s); // In case we currently sending a lot of data
	status.first_request_time = time_now();

	std::cout << "Sending negotiation packet to peer" << std::endl;
	socket.send_data(create_message(MESSAGE_TYPE::NEGOTIATION_TEST, begin));

	status.state = NegotiationState::AWAITING_NEGOTIATION_ACK;
}

void send_negotiation_packets(IDataSocketWrapper& socket, NegotiationStatus& status)
{
	if (status.state != NegotiationState::AWAITING_NEGOTIATION_ACK && status.state != NegotiationState::NEGOTIATING)
		return;

	status.state = NegotiationState::NEGOTIATING;

	// Send as fast as possible
	if (status.send_params.send_speed <= 0.f)
	{
		for (; status.num_sent < status.send_params.num_packets; ++status.num_sent)
		{
			socket.send_data(create_negotiation_packet(status.num_sent, status.send_params.packet_byte_size));
		}
		status.last_send_time = time_now();
		status.state = NegotiationState::AWAITING_NEGOTIATION_REPORT;
		std::cout << "Sent all Negotiation packets, awaiting report" << std::endl;
	}

	// Send only as many packets as matches the bandwidth
	else
	{
		if (status.num_sent == 0)
		{
			socket.send_data(create_negotiation_packet(0, status.send_params.packet_byte_size));
			status.num_sent = 1;
			status.last_send_time = time_now();
			auto time_for_one_message = s_duration((((float)status.send_params.packet_byte_size) / (float)KILOBYTE) / status.send_params.send_speed);
			std::cout << "We'll use " << duration_to_str(time_for_one_message) << " to send one message" << std::endl;
			std::cout << "Packets sent: " << 1.f / (float)status.send_params.num_packets * 100.f << "%";
			return;
		}

		// Only send if we have waited long enough
		auto& bandwidth = status.send_params.send_speed;
		auto& last_send = status.last_send_time;

		auto time_for_one_message = s_duration((((float)status.send_params.packet_byte_size) / (float)KILOBYTE) / bandwidth);

		auto time_since = time_now() - last_send;
		if (time_since < time_for_one_message) // Return if it hasn't been at least one message worth of time
			return;

		int num_to_send = (int)floorf(time_since / time_for_one_message);
		for (int i = 0; i < num_to_send && status.num_sent < status.send_params.num_packets; ++i, ++status.num_sent)
		{
			socket.send_data(create_negotiation_packet(status.num_sent, status.send_params.packet_byte_size));
			last_send = last_send + time_for_one_message;
			std::cout << "\rPackets sent: " << (float)status.num_sent / (float)status.send_params.num_packets * 100.f << "%";
		}

		if (status.num_sent >= status.send_params.num_packets)
		{
			std::cout << "\rPackets sent: 100%" << std::endl;
			status.num_sent = status.send_params.num_packets;
			status.state = NegotiationState::AWAITING_NEGOTIATION_REPORT;
			last_send = time_now();
			std::cout << "Sent all Negotiation packets, awaiting report" << std::endl;
		}
	}
}

void check_for_counting_timeout(IDataSocketWrapper& socket, NegotiationStatus& status)
{
	if (status.state != NegotiationState::COUNTING_PACKETS)
		return;

	if (!is_real_time(status.last_data_receive_time))
	{
		if (time_now() - status.received_negotiation_begin_time > NEGOTIATION_TIMEOUT)
		{
			// Failed
			status.state = NegotiationState::NOT_NEGOTIATING;
		}
		return;
	}

	if (time_now() - status.last_data_receive_time > NEGOTIATION_PERIOD)
	{
		// Report early
		std::cout << "Reporting early" << std::endl;
		send_negotiation_report(socket, status);
	}
}

void check_for_ack_timeout(IDataSocketWrapper& socket, NegotiationStatus& status)
{
	if (status.state == NegotiationState::AWAITING_NEGOTIATION_ACK && is_real_time(status.first_request_time) && time_now() - status.first_request_time > NEGOTIATION_TIMEOUT)
	{
		std::cout << "Negotiation failed to receive an acknowledgement" << std::endl;
		status.state = NegotiationState::NOT_NEGOTIATING;
	}
}

void check_for_report_timeout(IDataSocketWrapper& socket, NegotiationStatus& status)
{
	auto diff = time_now() - status.last_send_time;
	if (status.state == NegotiationState::AWAITING_NEGOTIATION_REPORT && is_real_time(status.last_send_time) && diff > NEGOTIATION_TIMEOUT)
	{
		std::cout << "Negotiation failed to receive a response in time (it was " << duration_to_str(diff) << " too late)" << std::endl;
		status.state = NegotiationState::NOT_NEGOTIATING;
	}
}

void send_negotiation_ack(IDataSocketWrapper& socket, NegotiationStatus& status)
{
	socket.send_data(create_message(MESSAGE_TYPE::NEGOTIATION_TEST_ACK));
	status.state = NegotiationState::COUNTING_PACKETS;
	status.received_negotiation_begin_time = time_now();
}

void send_negotiation_report(IDataSocketWrapper& socket, NegotiationStatus& status)
{
	if (status.state != NegotiationState::COUNTING_PACKETS)
	{
		std::cout << "Can not send negotiation report, we weren't counting packets! state: " << ns_to_str(status.state) << std::endl;
		return;
	}
	
	if (time_now() - status.last_data_receive_time < 1s)
		std::this_thread::sleep_for(1s);

	auto& report = status.receive_params;
	report.packet_loss = 1.f - (float)report.packets_received / (float)report.packets_expected;
	
	auto data_duration = (status.last_data_receive_time - status.first_data_receive_time) * ((float)report.packets_received + 1.f) / (float)report.packets_received;
	auto duration_in_secs = duration_cast<s_duration_float>(data_duration).count();
	auto data_in_kb = (float)((report.packets_received * status.send_params.packet_byte_size) / KILOBYTE);

	report.estimated_bandwidth = data_in_kb / duration_in_secs;

	socket.send_data(create_message(MESSAGE_TYPE::NEGOTATION_REPORT, report));

	status.state = NegotiationState::NEGOTIATED_AS_RECEIVER;

	status.first_data_receive_time = s_time{};
	status.last_data_receive_time = s_time{};
	status.received_negotiation_begin_time = s_time{};
	status.last_send_time = s_time{};

	std::cout << "Successfully helped peer negotiate" << std::endl;
	std::cout << "Peer has " << report.estimated_bandwidth << " KB/s bandwidth with " << (int)(report.packet_loss * 100.f) << "." << (int)(report.packet_loss * 1000.f) % 10 << "% packet loss" << std::endl;
}

Message create_negotiation_packet(int id, int packet_size)
{
	int32_t id_real = id;

	int remaining_bytes = packet_size - sizeof(id_real) - MESSAGE_OVERHEAD;
	std::vector<char> padding{ (size_t)remaining_bytes, (char)0, std::allocator<char>() };

	return create_message(MESSAGE_TYPE::NEGOTATION_TEST_DATA, id_real, padding);
}

void on_receive_negotiation_begin(const Message& msg, IDataSocketWrapper& socket, NegotiationStatus& status)
{
	if (is_already_negotiation_status(status.state))
	{
		std::cout << "Can not begin negotiating, we're already negotiating! state: " << ns_to_str(status.state) << std::endl;
		return;
	}

	if (msg.Type != MESSAGE_TYPE::NEGOTIATION_TEST)
	{
		std::cout << "Received request to negotiate with a message that isn't a NEGOTIATE_TEST" << std::endl;
		return;
	}
	std::cout << "Received request to negotiate bandwidth" << std::endl;

	int read_index = 0;
	auto begin = msg.read_type<NegotiationBegin>(read_index);

	status.send_params = begin;
	status.receive_params.packets_expected = status.send_params.num_packets;
	status.receive_params.estimated_bandwidth = 0.f;
	status.receive_params.packet_loss = 0.f;
	status.receive_params.packets_received = 0;

	socket.send_data(create_message(MESSAGE_TYPE::NEGOTIATION_TEST_ACK));

	status.received_negotiation_begin_time = time_now();
	status.state = NegotiationState::COUNTING_PACKETS;
}

void on_receive_negotiation_ack(const Message& msg, IDataSocketWrapper& socket, NegotiationStatus& status)
{
	if (msg.Type != MESSAGE_TYPE::NEGOTIATION_TEST_ACK)
	{
		std::cout << "Received negotiation acknowledgement during invalid state: " << ns_to_str(status.state) << std::endl;
		return;
	}

	std::cout << "Received negotiation acknowledgement" << std::endl;

	if (status.state != NegotiationState::AWAITING_NEGOTIATION_ACK)
	{
		std::cout << "Received Negotiation Ack when socket was not waiting, state: " << ns_to_str(status.state) << std::endl;
		return;
	}

	std::cout << "Received Negotiation Acknowledgement" << std::endl;
	status.state = NegotiationState::NEGOTIATING;
}

void on_receive_data_packet(const Message& msg, IDataSocketWrapper& socket, NegotiationStatus& status)
{
	if (status.state != NegotiationState::COUNTING_PACKETS)
	{
		return;
	}

	if (msg.Type != MESSAGE_TYPE::NEGOTATION_TEST_DATA)
		return;

	int read_index = 0;
	auto packet_index = msg.read_type<int32_t>(read_index);
	
	(void)packet_index; // Unused for now

	status.receive_params.packets_received++;
	if (!is_real_time(status.first_data_receive_time))
		status.first_data_receive_time = time_now();

	status.last_data_receive_time = time_now();

	if (status.receive_params.packets_received >= status.receive_params.packets_expected)
		send_negotiation_report(socket, status);
}

void on_receive_report(const Message& msg, IDataSocketWrapper& socket, NegotiationStatus& status)
{
	if (status.state != NegotiationState::AWAITING_NEGOTIATION_REPORT)
	{
		std::cout << "Received report when we aren't expecting one! state: " << ns_to_str(status.state) << std::endl;
		return;
	}

	if (msg.Type != MESSAGE_TYPE::NEGOTATION_REPORT)
		return;

	std::cout << "Received Report" << std::endl;

	int read_index = 0;
	auto report = msg.read_type<NegotiationReport>(read_index);

	status.receive_params = report;
	status.state = NegotiationState::NEGOTIATED_AS_SENDER;

	status.last_send_time = s_time{};
	status.last_data_receive_time = s_time{};
	status.first_data_receive_time = s_time{};

	std::cout << "Successfully negotiated bandwidth. Results: Esimated bandwidth: " << report.estimated_bandwidth << " KB/s " << (int)(report.packet_loss * 100.f) << "." << (int)(report.packet_loss * 1000.f) % 10 << "% packet loss (" << report.packets_received << "/" << report.packets_expected << ")" << std::endl;
}

std::string ns_to_str(NegotiationState status)
{
	switch (status)
	{
	case NegotiationState::AWAITING_NEGOTIATION_ACK:
		return "AWAITING_NEGOTIATION_ACK: Waiting for a negotiation confirmation";
	case NegotiationState::NEGOTIATING:
		return "NEGOTIATING: Sending Negotiation packets";
	case NegotiationState::AWAITING_NEGOTIATION_REPORT:
		return "AWAITING_NEGOTIATION_REPORT: Waiting for a Negotiation Report";
	case NegotiationState::COUNTING_PACKETS:
		return "COUNTING_PACKETS: Counting incoming Negotiation Packets";
	case NegotiationState::DELAY_BEFORE_REPORTING:
		return "DELAY_BEFORE_REPORTING: Delaying before Reporting Negotiation results";
	case NegotiationState::NEGOTIATED_AS_SENDER:
		return "NEGOTIATED_AS_SENDER: Successfully negotiated as sender";
	case NegotiationState::NEGOTIATED_AS_RECEIVER:
		return "NEGOTIATED_AS_RECEIVER: Successfully negotiated as receiver";

	default:
	case NegotiationState::NOT_NEGOTIATING:
		return "Not Negotiating";
	}
}

bool INegotiator::should_send_data() const
{
	if (!is_real_time(_last_data_send))
		return true;

	if (_negotiation_status.receive_params.estimated_bandwidth <= 0.f)
		return true;

	return time_now() > _last_data_send;
}

bool INegotiator::should_send_data(int data_size) const
{
	if (!is_real_time(_last_data_send))
		return true;

	if (_negotiation_status.receive_params.estimated_bandwidth <= 0.f)
		return true;

	const auto& bandwidth = _negotiation_status.receive_params.estimated_bandwidth;

	float kb = (float)data_size / (float)KILOBYTE;
	float required_time = kb / bandwidth; // Amount of time we would 'consume' by sending this amount of data
	s_duration required_time_time{ required_time };

	return time_now() > (_last_data_send + required_time_time);
}

void INegotiator::sent_data(int data_size)
{
	if (_negotiation_status.receive_params.estimated_bandwidth <= 0.f)
		return;

	if (!is_real_time(_last_data_send))
	{
		_last_data_send = time_now();
		return;
	}

	const auto& bandwidth = _negotiation_status.receive_params.estimated_bandwidth;

	float kb = (float)data_size / (float)KILOBYTE;
	float required_time = kb / bandwidth; // Amount of time we would 'consume' by sending this amount of data
	s_duration required_time_time{ required_time };

	_last_data_send = _last_data_send + required_time_time;
	if (time_now() - required_time_time > _last_data_send)
		_last_data_send = time_now() - required_time_time;
}

INegotiator::INegotiator() : _negotiation_status(NegotiationStatus::BLANK_STATE), _last_data_send()
{
}

bool INegotiator::is_negotiating() const
{
	return is_already_negotiation_status(_negotiation_status.state);
}

bool INegotiator::has_negotiated() const
{
	return _negotiation_status.state == NegotiationState::NEGOTIATED_AS_SENDER;
}

void INegotiator::begin_negotiation(float bandwidth, int num_packets, int packet_size)
{
	::begin_negotiation(*this, _negotiation_status, bandwidth, num_packets, packet_size);
}

bool INegotiator::negotiate()
{
	switch (_negotiation_status.state)
	{
	case NegotiationState::NEGOTIATING:
		send_negotiation_packets(*this, _negotiation_status);
		break;
	case NegotiationState::COUNTING_PACKETS:
		check_for_counting_timeout(*this, _negotiation_status);
		break;
	case NegotiationState::AWAITING_NEGOTIATION_ACK:
		check_for_ack_timeout(*this, _negotiation_status);
		break;
	case NegotiationState::AWAITING_NEGOTIATION_REPORT:
		check_for_report_timeout(*this, _negotiation_status);
		break;
	}

	if (_negotiation_status.state == NegotiationState::NEGOTIATED_AS_SENDER)
		return true;
	return false;
}

NegotiationReport INegotiator::get_negotiation_report()
{
	if (_negotiation_status.state != NegotiationState::NEGOTIATED_AS_SENDER)
		return _negotiation_status.receive_params;
	return NegotiationReport{};
}

void INegotiator::on_receive_negotiation_begin(const Message& msg)
{
	::on_receive_negotiation_begin(msg, *this, _negotiation_status);
}

void INegotiator::on_receive_negotiation_ack(const Message& msg)
{
	::on_receive_negotiation_ack(msg, *this, _negotiation_status);
}

void INegotiator::on_receive_data_packet(const Message& msg)
{
	::on_receive_data_packet(msg, *this, _negotiation_status);
}

void INegotiator::on_receive_report(const Message& msg)
{
	::on_receive_report(msg, *this, _negotiation_status);
}
