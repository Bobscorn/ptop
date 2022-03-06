#include "negotiation.h"

#include <thread>
#include <math.h>
#include <cstring>


bool Negotiator::should_send_data(int data_size) const
{
	if (!is_real_time(_last_data_send))
		return true;
		
	float kb = (float)data_size / (float)KILOBYTE;
	float required_time = kb / _KB_PER_SECOND; // Amount of time we would 'consume' by sending this amount of data
	s_duration required_time_time{ required_time };

	return time_now() > (_last_data_send + required_time_time);
}

void Negotiator::sent_data()
{
	_last_data_send = time_now();
}

Negotiator::Negotiator() :  _last_data_send()
{
}
