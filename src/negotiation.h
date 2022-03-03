#pragma once

#include <memory>

#include "message.h"
#include "interfaces.h"
#include "time.h"

/**
 * Negotiation Should go as follows:
 * 
 * Sender Prepares a NegotiationBegin struct with:
 * - number of messages 
 * - size of messages 
 * - transmission speed
 * It stores this struct and sends it to the peer.
 * The sender now enters AWAITING_NEGOTIATION_ACK state, waiting for a response
 * 
 * The Receiver, in either NEGOTIATED_AS_* or NOT_NEGOTIATING states, receives the NegotiationBegin struct.
 * It stores the struct, and responds with a NEGOTIATION_TEST_ACK message.
 * The receiver then enters NegotiationState::COUNTING and looks for NEGOTIATION_TEST_DATA messages
 * 
 * Sender sees this response and begins sending the agreed upon number of message at the agreed upon size at the agreed upon speed.
 * Once the sender has sent the last message, it enters the AWAITING_NEGOTIATION_REPORT state.
 * 
 * The Receiver counts the messages, records their timings, and waits for up to NEGOTIATION_PERIOD after the *first* NEGOTIATION_TEST_DATA message it receives.
 * Once the NEGOTIATION_PERIOD has elapsed, it produces a NegotiationReport struct, stores it, and sends it to the peer.
 * The Receiver has negotiated, and now enters NEGOTIATED_AS_RECEIVER state.
 * The Receiver has finished, it will do no more work.
 * 
 * The Sender either:
 * - Receives the report, stores it, indicates to the caller that negotiation has succeeded
 * or
 * - Times out before receiving any report and indicates failure
 * If it succeeds it will set its state to NEGOTIATED_AS_SENDER
 * If it fails it will set its state to NOT_NEGIATING
 * Either way it will do no more work, negotiating has either completed or failed.
 */


constexpr int DEFAULT_NEGOTIATION_TEST_SIZE = 4 * KILOBYTE;

extern const s_duration NEGOTIATION_PERIOD; // Amount of time a receiving negotiator will wait after the NegotiationBegin before sending the NegotiationReport message
extern const s_duration NEGOTIATION_ACK_TIMEOUT;
extern const s_duration NEGOTIATION_TIMEOUT; // Amount of time a sending negotiator will wait for a NegotiationReport before failing Negotiation

struct NegotiatedConnection
{
	float BandwidthKBps; // Negotiated Bandwidth in KB/s
	float ExpectedPacketLoss; // Decimal percentage 0..1
};

enum class NegotiationState
{
	NOT_NEGOTIATING = 0,

	AWAITING_NEGOTIATION_ACK, // The state of a socket that has sent a NegotiationBegin message
	NEGOTIATING, // The state of a socket that is sending NegotiationPacket messages
	AWAITING_NEGOTIATION_REPORT, // The state if of a socket that has sent all NegotiationPacket messages and is waiting for a NegotiationReport message

	COUNTING_PACKETS, // The state of a socket that is counting the incoming NegotiationPacket messages
	DELAY_BEFORE_REPORTING, // The state of a socket that is waiting before sending a report back (to avoid congestion)

	NEGOTIATED_AS_SENDER, // The state of a socket that has received a report, and will remain in this state until another negotiation
	NEGOTIATED_AS_RECEIVER, // The state of a socket that has sent a report
};

struct NegotiationReport
{
	int packets_received; // Number of packets actually received
	int packets_expected; // Number of packets that was expected (from a NegotiationBegin message)
	float estimated_bandwidth; // The bandwidth we estimate from the packets we received, in KB/s
	float packet_loss; // Percentage of packets lost (0..1)
};

struct NegotiationBegin
{
	int num_packets; // Number of NegotiationPacket messages that will be sent
	int packet_byte_size; // Size of NegotiationPacket messages
	float send_speed; // Speed at which the sender will send data at, in KB/s, speed of 0 indicates as fast as possible
};

struct NegotiationPacket
{
	int packet_id; // The index of this packet
};

struct NegotiationStatus
{
	NegotiationState state = NegotiationState::NOT_NEGOTIATING;

	NegotiationBegin send_params;
	int num_sent;
	s_time_d last_send_time;

	NegotiationReport receive_params;
	s_time received_negotiation_begin_time;
	s_time first_data_receive_time;
	s_time last_data_receive_time;

	s_time first_request_time;

	static const NegotiationStatus BLANK_STATE;
};

bool is_already_negotiation_status(NegotiationState state);

void begin_negotiation(IDataSocketWrapper& socket, NegotiationStatus& status, float bandwidth, int num_packets, int packet_size);
void send_negotiation_packets(IDataSocketWrapper& socket, NegotiationStatus& status);

void check_for_counting_timeout(IDataSocketWrapper& socket, NegotiationStatus& status);
void check_for_ack_timeout(IDataSocketWrapper& socket, NegotiationStatus& status);
void check_for_report_timeout(IDataSocketWrapper& socket, NegotiationStatus& status);

void send_negotiation_ack(IDataSocketWrapper& socekt, NegotiationStatus& status);
void send_negotiation_report(IDataSocketWrapper& socket, NegotiationStatus& status);

Message create_negotiation_packet(int id, int packet_size);

void on_receive_negotiation_begin(const Message& msg, IDataSocketWrapper& socket, NegotiationStatus& status);
void on_receive_negotiation_ack(const Message& msg, IDataSocketWrapper& socket, NegotiationStatus& status);
void on_receive_data_packet(const Message& msg, IDataSocketWrapper& socket, NegotiationStatus& status);
void on_receive_report(const Message& msg, IDataSocketWrapper& socket, NegotiationStatus& status);

std::string ns_to_str(NegotiationState status);

struct INegotiator : virtual public IDataSocketWrapper
{
protected:
	NegotiationStatus _negotiation_status;

	s_time_d _last_data_send;

public:
	INegotiator();
	bool should_send_data() const;
	bool should_send_data(int data_size) const;
	void sent_data(int data_size);

	bool is_negotiating() const;
	bool has_negotiated() const;

	void begin_negotiation(float bandwidth, int num_packets, int packet_size);
	bool negotiate(); // Returns whether negotiating has completed
	NegotiationReport get_negotiation_report();

	void on_receive_negotiation_begin(const Message& msg);
	void on_receive_negotiation_ack(const Message& msg);
	void on_receive_data_packet(const Message& msg);
	void on_receive_report(const Message& msg);
};