#ifndef HAND_SHAKE_H
#define HAND_SHAKE_H
#include <stdint.h>
#include <string>
#include <Windows.h>
using namespace std;
class CHandShake
{
public:
	enum HAND_SHAKE_STATE
	{
		HAND_SHAKE_STATE_C0C1,
		HAND_SHAKE_STATE_C2,
		HAND_SHAKE_STATE_FINISH
	};
	CHandShake(SOCKET fd, std::string &send_q);
	bool handle();
	void handle_C0C1();
	void handle_C1_simple();
#ifdef ENABLE_OPENSSL
	void handle_C1_complex();
	string get_C1_digest(const uint8_t *ptr,char **digestPos);
	string get_C1_key(const uint8_t *ptr);
	void check_C1_Digest(const string &digest,const string &data);
	void send_complex_S0S1S2(int schemeType,const string &digest);
#endif //ENABLE_OPENSSL

	void handle_C2();
private:
	string m_strRcvBuf;
	char m_recv_buf[4096];
	//function<void()> m_nextHandle;
	SOCKET m_fd;
	std::string &send_queue;
	HAND_SHAKE_STATE shake_state;
};

#endif