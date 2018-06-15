#include "dns-project.h"

//Client  -->>  127.0.0.1

#define DNS_SERVER_ADDRESS                      DNS_SERVER_0

//打印运行指令
void usage(char **argv);

//设置socket
void socket_setup();

//关闭socket
void socket_close();

//查询记录
void tcp_query();

//接收 解析Response
void resolve_tcp_response_packet();

//DNS Local Server的socket
int server_socket;

//参数数量
int arg_num;

//参数值
char **arg_v;

//查询的数量
uint16_t queries;

//表明递归或迭代
uint8_t rd;

//Buffer
u_char buf[TCP_BUFFER_CAPACITY];

//记录发送出请求和接收回应的时刻
struct timeval start, end;

//Hello world
int main(int argc, char **argv) {
	//参数数目不对时
	if (argc < 2 || argc % 2 == 1)
		usage(argv);

	//初始化socket和地址结构体
	socket_setup();

	arg_num = argc;
	arg_v = argv;

	if (!strcmp(argv[1], "-r")) {
		rd = DNS_RECURSIVE;
	} else if (!strcmp(argv[1], "-i")) {
		rd = DNS_ITERATIVE;
	} else {
		usage(argv);
	}

	tcp_query();

	for (int i = 0; i < queries; i++) {
		//解析Response
		resolve_tcp_response_packet();
	}

	//关闭socket
	socket_close();
	return 0;
}

//打印运行指令
void usage(char **argv) {
	printf("Usage: %s -r|-i -q=<type> <name> [-q=<type> <name>]*N\n"
	       "-r: recursive query.\n"
	       "-i: iterative query.\n"
	       "type: A CNAME MX\n", argv[0]);
	exit(0);
}

//设置socket
void socket_setup() {
	//创建socket
	printf("Creating a socket...");
	if ((server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		printf("socket() failed.\n");
		exit(1);
	}
	printf("OK!\n");

	//设置地址结构体
	printf("Initializing socket address...");
	struct sockaddr_in server_add;
	memset(&server_add, 0, sizeof(struct sockaddr_in));
	server_add.sin_family = AF_INET;
	server_add.sin_port = htons(DNS_SERVER_PORT);
	server_add.sin_addr.s_addr = inet_addr(DNS_SERVER_ADDRESS);
	printf("OK!\n");

	printf("Connecting to local DNS server...");
	connect(server_socket, (struct sockaddr *) &server_add, sizeof(server_add));
	printf("OK!\n");
}

//关闭socket
void socket_close() {
	printf("Closing the socket...");
	close(server_socket);
	printf("OK!\n");
}

//查询记录
void tcp_query() {
	bzero(buf, TCP_BUFFER_CAPACITY);

	printf("Constructing a DNS packet...");
	size_t loc = sizeof(uint16_t); //TCP DNS包的前两个字节是包的大小

	//Number of queries in packet
	queries = (uint16_t) ((arg_num - 2) / 2);

	struct DNS_Header *pHeader = construct_header(0, DNS_QUERY, rd, DNS_RCODE_NO_ERROR, queries, 0, 0, 0);

	struct DNS_Query **pQueries = malloc(sizeof(struct DNS_Query) * queries);

	for (int i = 2; i < arg_num; i += 2) {
		int num = (i - 2) / 2;
		pQueries[num] = malloc(sizeof(struct DNS_Query));
		if (!strcmp(arg_v[i], "-q=A")) {
			pQueries[num]->name = (u_char *) arg_v[i + 1];
			pQueries[num]->type = DNS_TYPE_A;
		} else if (!strcmp(arg_v[i], "-q=CNAME")) {
			pQueries[num]->name = (u_char *) arg_v[i + 1];
			pQueries[num]->type = DNS_TYPE_CNAME;
		} else if (!strcmp(arg_v[i], "-q=PTR")) {
			pQueries[num]->name = (u_char *) ip2arpa(arg_v[i + 1]); //1.2.3.4 -> 4.3.2.1.in-addr.arpa
			pQueries[num]->type = DNS_TYPE_PTR;
		} else if (!strcmp(arg_v[i], "-q=MX")) {
			pQueries[num]->name = (u_char *) arg_v[i + 1];
			pQueries[num]->type = DNS_TYPE_MX;
		} else {
			usage(arg_v);
		}
		pQueries[num]->class = DNS_CLASS_IN;
	}

	struct DNS_Record **pAnswers = NULL, **pAuth = NULL, **pAdd = NULL; //Useless here

	loc = construct_dns_packet(loc, buf, pHeader, pQueries, pAnswers, pAuth, pAdd);

	uint16_t dns_packet_size = htons((uint16_t) (loc - 2));
	printf("OK!\n");

	//TCP DNS packet前两个字节表示DNS packet的长度
	memcpy(buf, &dns_packet_size, sizeof(uint16_t));

	printf("Sending a DNS packet...Length: <%zu>...", loc - 2);
	send(server_socket, buf, loc, 0);
	printf("OK!\n");

	//记录时间
	gettimeofday(&start, NULL);
}

//接收 解析Response
void resolve_tcp_response_packet() {
	uint16_t length = 0;

	recv(server_socket, &length, sizeof(uint16_t), 0);
	length = ntohs(length);
	bzero(buf, length);

	printf("Receiving a DNS packet...Length: <%hu>...", length);
	recv(server_socket, buf, length, 0);
	printf("OK!\n");

	gettimeofday(&end, NULL);
	printf("Server <%s> response in %lf seconds.\n", DNS_SERVER_ADDRESS,
	       end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0);

	printf("==================================================\n");
	size_t loc = 0;
	u_char *reader = buf;

	//Header
	struct DNS_Header *pHeader = resolve_header(&loc, reader);
	reader += loc;

	//Queries
	printf("<%hu> queries.\n", pHeader->queries);
	for (int i = 0; i < pHeader->queries; i++) {
		resolve_query(&loc, buf, reader);
		reader += loc;
	}

	//Answers
	printf("<%hu> answers.\n", pHeader->answers);
	for (int i = 0; i < pHeader->answers; i++) {
		resolve_rr(&loc, buf, reader);
		reader += loc;
	}

	//Authoritative records
	printf("<%hu> authoritative records.\n", pHeader->auth_rr);
	for (int i = 0; i < pHeader->auth_rr; i++) {
		resolve_rr(&loc, buf, reader);
		reader += loc;
	}

	//Additional records
	printf("<%hu> additional records.\n", pHeader->add_rr);
	for (int i = 0; i < pHeader->add_rr; i++) {
		resolve_rr(&loc, buf, reader);
		reader += loc;
	}
	printf("==================================================\n");
}
