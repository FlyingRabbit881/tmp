//#include "rtmp.h"
#include "HandShake.h"
#define HANDSHAKE_PLAINTEXT	0x03

#define RANDOM_LEN		(1536 - 8)
#ifdef ENABLE_OPENSSL
#include <openssl/hmac.h>
static string openssl_HMACsha256(const void *key,unsigned int key_len,
								 const void *data,unsigned int data_len){
	//std::shared_ptr<char> out(new char[32],[](char *ptr){delete [] ptr;});
	char *out = new char[32];
	unsigned int out_len;
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, key_len, EVP_sha256(), NULL);
	HMAC_Update(&ctx, (unsigned char*)data, data_len);
	HMAC_Final(&ctx, (unsigned char *)out, &out_len);
	HMAC_CTX_cleanup(&ctx);
	string s = string(out,out_len);
	delete []out;
	return s;
}
#endif //ENABLE_OPENSSL



#define C1_DIGEST_SIZE 32
#define C1_KEY_SIZE 128
#define C1_SCHEMA_SIZE 764
#define C1_HANDSHARK_SIZE (RANDOM_LEN + 8)
#define C1_FPKEY_SIZE 30
#define S1_FMS_KEY_SIZE 36
#define S2_FMS_KEY_SIZE 68
#define C1_OFFSET_SIZE 4

#pragma pack(push, 1)
class RtmpHandshake {
public:
    RtmpHandshake(uint32_t _time, uint8_t *_random = nullptr) {
		memset(zero, 0, sizeof(zero));
        _time = htonl(_time);
        memcpy(timeStamp, &_time, 4);
        if (!_random) {
            random_generate((char *) random, sizeof(random));
        } else {
            memcpy(random, _random, sizeof(random));
        }
    }
    uint8_t timeStamp[4];
    uint8_t zero[4];
    uint8_t random[RANDOM_LEN];
    void random_generate(char* bytes, int size) {
        static char cdata[] = { 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x2d, 0x72,
            0x74, 0x6d, 0x70, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
            0x2d, 0x77, 0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x2d, 0x77, 0x69,
            0x6e, 0x74, 0x65, 0x72, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
            0x40, 0x31, 0x32, 0x36, 0x2e, 0x63, 0x6f, 0x6d };
        for (int i = 0; i < size; i++) {
            bytes[i] = cdata[rand() % (sizeof(cdata) - 1)];
        }
    }
};
#pragma pack(pop)


static size_t recv_all(SOCKET fd, void *buf, size_t len)
{
	size_t pos = 0;
	while (pos < len) {
		int bytes = recv(fd, (char *) buf + pos, len - pos, 0);
		if (bytes < 0) {

			int err = WSAGetLastError();
			if (err == 0 || err == EWOULDBLOCK || err == WSAEWOULDBLOCK)
				continue;
			throw std::runtime_error(
				"unable to recv: %s");
		}
		if (bytes == 0)
			break;
		pos += bytes;
	}
	return pos;
}

static size_t send_all(SOCKET fd, const void *buf, size_t len)
{
	size_t pos = 0;
	while (pos < len) {
		int written = send(fd, (const char *) buf + pos, len - pos, 0);
		if (written < 0) {
			int err = WSAGetLastError();
			if (err == 0 || err == EWOULDBLOCK || err == WSAEWOULDBLOCK)
				continue;
			throw std::runtime_error(
			("unable to send:"));
		}
		if (written == 0)
			break;
		pos += written;
	}
	return pos;
}

////for server ////
CHandShake::CHandShake(SOCKET fd, std::string &send_q):m_fd(fd), send_queue(send_q)
{
	shake_state = HAND_SHAKE_STATE_C0C1;
}
bool CHandShake::handle()
{
	if (shake_state == HAND_SHAKE_STATE_C0C1)
		handle_C0C1();
	else if (shake_state == HAND_SHAKE_STATE_C2)
		handle_C2();
	if (shake_state == HAND_SHAKE_STATE_FINISH)
		return true;
	return false;
}
void CHandShake::handle_C0C1() {
	int c0c1_size = 1 + C1_HANDSHARK_SIZE;
	int len = recv(m_fd, m_recv_buf, c0c1_size - m_strRcvBuf.size(), 0);

	if (len <= 0)
	{
		throw std::runtime_error(
			("unable to send:"));
	}

	m_strRcvBuf.append(m_recv_buf, len);

	if (m_strRcvBuf.size() < c0c1_size) {
		//need more data!
		return;
	}
	if (m_strRcvBuf[0] != HANDSHAKE_PLAINTEXT) {
		throw std::runtime_error("only plaintext[0x03] handshake supported");
	}
	if(memcmp(m_strRcvBuf.c_str() + 5,"\x00\x00\x00\x00",4) ==0 ){
		//simple handsharke
		handle_C1_simple();
	}else{
#ifdef ENABLE_OPENSSL
		//complex handsharke
		handle_C1_complex();
#else
		WarnL << "未打开ENABLE_OPENSSL宏，复杂握手采用简单方式处理！";
		handle_C1_simple();
#endif//ENABLE_OPENSSL
	}
	m_strRcvBuf.erase(0, 1 + C1_HANDSHARK_SIZE);
	shake_state = HAND_SHAKE_STATE_C2;
}
void CHandShake::handle_C1_simple(){
	//发送S0
	char handshake_head = HANDSHAKE_PLAINTEXT;
	send(m_fd, &handshake_head, 1, 0);
	//发送S1
	RtmpHandshake s1(0);
	//onSendRawData((char *) &s1, C1_HANDSHARK_SIZE);
	send_all(m_fd, (char*)&s1, C1_HANDSHARK_SIZE);
	//发送S2
	//onSendRawData(m_strRcvBuf.c_str() + 1, C1_HANDSHARK_SIZE);
	send_all(m_fd, m_strRcvBuf.c_str() + 1, C1_HANDSHARK_SIZE);
	//等待C2
	/*m_nextHandle = [this]() {
		handle_C2();*/
	//};
}
#ifdef ENABLE_OPENSSL
void CHandShake::handle_C1_complex(){
	//参考自：http://blog.csdn.net/win_lin/article/details/13006803
	//skip c0,time,version
	const char *c1_start = m_strRcvBuf.data() + 1;
	const char *schema_start = c1_start + 8;
	char *digest_start;
	try{
		/* c1s1 schema0
		time: 4bytes
		version: 4bytes
		key: 764bytes
		digest: 764bytes
		 */
		auto digest = get_C1_digest((uint8_t *)schema_start + C1_SCHEMA_SIZE,&digest_start);
		string c1_joined(c1_start,C1_HANDSHARK_SIZE);
		c1_joined.erase(digest_start - c1_start , C1_DIGEST_SIZE );
		check_C1_Digest(digest,c1_joined);

		send_complex_S0S1S2(0,digest);
		 printf( "schema0\n");
	}catch(std::exception &ex){
		//貌似flash从来都不用schema1
		printf( "try rtmp complex schema0 failed:\n");
		try{
			/* c1s1 schema1
			time: 4bytes
			version: 4bytes
			digest: 764bytes
			key: 764bytes
			 */
			auto digest = get_C1_digest((uint8_t *)schema_start,&digest_start);
			string c1_joined(c1_start,C1_HANDSHARK_SIZE);
			c1_joined.erase(digest_start - c1_start , C1_DIGEST_SIZE );
			check_C1_Digest(digest,c1_joined);

			send_complex_S0S1S2(1,digest);
			printf("schema1\n");
		}catch(std::exception &ex){
			//WarnL << "try rtmp complex schema1 failed:" <<  ex.what();
			handle_C1_simple();
		}
	}
}


static uint8_t FMSKey[] = {
    0x47, 0x65, 0x6e, 0x75, 0x69, 0x6e, 0x65, 0x20,
    0x41, 0x64, 0x6f, 0x62, 0x65, 0x20, 0x46, 0x6c,
    0x61, 0x73, 0x68, 0x20, 0x4d, 0x65, 0x64, 0x69,
    0x61, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
    0x20, 0x30, 0x30, 0x31, // Genuine Adobe Flash Media Server 001
    0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8,
    0x2e, 0x00, 0xd0, 0xd1, 0x02, 0x9e, 0x7e, 0x57,
    0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab,
    0x93, 0xb8, 0xe6, 0x36, 0xcf, 0xeb, 0x31, 0xae
}; // 68

static uint8_t FPKey[] = {
    0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E, 0x65, 0x20,
    0x41, 0x64, 0x6F, 0x62, 0x65, 0x20, 0x46, 0x6C,
    0x61, 0x73, 0x68, 0x20, 0x50, 0x6C, 0x61, 0x79,
    0x65, 0x72, 0x20, 0x30, 0x30, 0x31, // Genuine Adobe Flash Player 001
    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8,
    0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E, 0x7E, 0x57,
    0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
    0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
}; // 62
void CHandShake::check_C1_Digest(const string &digest,const string &data){
	auto sha256 = openssl_HMACsha256(FPKey,C1_FPKEY_SIZE,data.data(),data.size());
	if(sha256 != digest){
		throw std::runtime_error("digest不匹配");
	}else{
		printf( "check rtmp complex handshark success!\n");
	}
}
string CHandShake::get_C1_digest(const uint8_t *ptr,char **digestPos){
	/* 764bytes digest结构
	offset: 4bytes
	random-data: (offset)bytes
	digest-data: 32bytes
	random-data: (764-4-offset-32)bytes
	 */
	int offset = 0;
	for(int i=0;i<C1_OFFSET_SIZE;++i){
		offset += ptr[i];
	}
	offset %= (C1_SCHEMA_SIZE - C1_DIGEST_SIZE - C1_OFFSET_SIZE);
	*digestPos = (char *)ptr + C1_OFFSET_SIZE + offset;
	string digest(*digestPos,C1_DIGEST_SIZE);
	//DebugL << "digest offset:" << offset << ",digest:" << hexdump(digest.data(),digest.size());
	return digest;
}
string CHandShake::get_C1_key(const uint8_t *ptr){
	/* 764bytes key结构
	random-data: (offset)bytes
	key-data: 128bytes
	random-data: (764-offset-128-4)bytes
	offset: 4bytes
	 */
	int offset = 0;
	for(int i = C1_SCHEMA_SIZE - C1_OFFSET_SIZE;i< C1_SCHEMA_SIZE;++i){
		offset += ptr[i];
	}
	offset %= (C1_SCHEMA_SIZE - C1_KEY_SIZE - C1_OFFSET_SIZE);
	string key((char *)ptr + offset,C1_KEY_SIZE);
	//DebugL << "key offset:" << offset << ",key:" << hexdump(key.data(),key.size());
	return key;
}
void CHandShake::send_complex_S0S1S2(int schemeType,const string &digest){
	//S1S2计算参考自：https://github.com/hitYangfei/golang/blob/master/rtmpserver.go
	//发送S0
	char handshake_head = HANDSHAKE_PLAINTEXT;
	//onSendRawData(&handshake_head, 1);
	//send_all(m_fd, &handshake_head, 1);
	send_queue.append(&handshake_head, 1);

	//S1
	RtmpHandshake s1(0);
	memcpy(s1.zero,"\x04\x05\x00\x01",4);
	char *digestPos;
	if(schemeType == 0){
		/* c1s1 schema0
		time: 4bytes
		version: 4bytes
		key: 764bytes
		digest: 764bytes
		 */
		get_C1_digest(s1.random + C1_SCHEMA_SIZE,&digestPos);
	}else{
		/* c1s1 schema1
		time: 4bytes
		version: 4bytes
		digest: 764bytes
		key: 764bytes
		 */
		get_C1_digest(s1.random,&digestPos);
	}
	char *s1_start = (char *)&s1;
	string s1_joined(s1_start,sizeof(s1));
	s1_joined.erase(digestPos - s1_start,C1_DIGEST_SIZE);
	string s1_digest = openssl_HMACsha256(FMSKey,S1_FMS_KEY_SIZE,s1_joined.data(),s1_joined.size());
	memcpy(digestPos,s1_digest.data(),s1_digest.size());
	//onSendRawData((char *) &s1, sizeof(s1));
	//send_all(m_fd, (char*)&s1, sizeof(s1));
	send_queue.append((char*)&s1, sizeof(s1));

	//S2
	string s2_key = openssl_HMACsha256(FMSKey,S2_FMS_KEY_SIZE,digest.data(),digest.size());
	RtmpHandshake s2(0);
	s2.random_generate((char *)&s2,8);
	string s2_digest = openssl_HMACsha256(s2_key.data(),s2_key.size(),&s2,sizeof(s2) - C1_DIGEST_SIZE);
	memcpy((char *)&s2 + C1_HANDSHARK_SIZE - C1_DIGEST_SIZE,s2_digest.data(),C1_DIGEST_SIZE);
	//onSendRawData((char *)&s2, sizeof(s2));
	//send_all(m_fd, (char*)&s2, sizeof(s2));
	send_queue.append((char*)&s2, sizeof(s2));
	//等待C2
	/*m_nextHandle = [this]() {
		handle_C2();
	};*/
}
#endif //ENABLE_OPENSSL
void CHandShake::handle_C2() {
	int c2_size = C1_HANDSHARK_SIZE;
	int len = recv(m_fd, m_recv_buf, c2_size - m_strRcvBuf.size(), 0);
	if (len <= 0)
	{
		throw std::runtime_error(
			("unable to send:"));
	}
	m_strRcvBuf.append(m_recv_buf, len);

	if (m_strRcvBuf.size() < C1_HANDSHARK_SIZE) {
		//need more data!
		return;
	}
	m_strRcvBuf.erase(0, C1_HANDSHARK_SIZE);
	//握手结束，进入命令模式
	if (!m_strRcvBuf.empty()) {
		
	}
//	m_nextHandle = [this]() {
	//};
	shake_state = HAND_SHAKE_STATE_FINISH;
}
