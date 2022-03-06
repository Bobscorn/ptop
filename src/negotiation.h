#pragma once

#include <memory>

#include "message.h"
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

constexpr float _KB_PER_SECOND = 3000;
constexpr int DEFAULT_NEGOTIATION_TEST_SIZE = 4 * KILOBYTE;

class Negotiator
{
protected:

	s_time_d _last_data_send;

	public:
		Negotiator();
		bool should_send_data(int data_size) const;
		void sent_data();

	private:

};