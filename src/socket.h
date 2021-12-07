#include <vector>

using namespace std;

class IReceiverSocket
{
public:
	
	virtual ~IReceiverSocket();

	virtual vector<char> receive_data() = 0;

	virtual bool is_open() = 0;
};

class IListenSocket
{
public:
	virtual ~IListenSocket();

	virtual ISenderSocket* accept_connection() = 0;
};

class ISenderSocket
{
public:

	virtual ~ISenderSocket();

	virtual bool send_data(const vector<char>& data) = 0;
};