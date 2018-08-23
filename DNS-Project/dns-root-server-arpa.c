#include "dns-project.h"

//in-addr ARPA DNS Server  -->>  127.2.2.2  in-addr-servers.arpa

#define DNS_SERVER_ADDRESS                      DNS_SERVER_2
#define DNS_FILE                                "dns-root-server-arpa.txt"

//设置服务器socket
void server_socket_setup();

//关闭服务器socket
void server_socket_close();

//解析DNS packet
void resolve_query_packet();

//解析并回应
void resolve_and_response();

//查询本地记录
int resolve_record(u_char *query_name, uint16_t type);

//回复记录
void
udp_response(struct DNS_Header *header, struct DNS_Query *query, struct DNS_Record **answers, struct DNS_Record **auth,
             struct DNS_Record **add);

//清空程序内存中原来的记录，或是初始化这些变量
void clean();

//查询文件记录
int resolve_file(char *filename, u_char *query_name, uint16_t type, int cache);

//DNS的socket
int upstream_server_socket, server_socket;

//Socket address
struct sockaddr_in upstream_server_add, server_add, client_add;

//Buffer
u_char server_buf[UDP_BUFFER_CAPACITY], client_buf[UDP_BUFFER_CAPACITY];

//请求的Header
struct DNS_Header *pHeader;

//要查询的记录
struct DNS_Query *pQuery;

//要回复的Header
struct DNS_Header *rHeader;

//要回复的Record
struct DNS_Record **rAnswers, **rAuth, **rAdd;

//Hello world
int main(int argc, char **argv) {
	//应该以root权限运行
	if (geteuid() != 0) {
		printf("This program should only be ran by root.\n");
		exit(0);
	}

	//初始化socket和地址结构体
	server_socket_setup();

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
	while (1) {
		bzero(client_buf, UDP_BUFFER_CAPACITY);
		clean();

		printf("Waiting for client...\n");
		socklen_t client_add_size = sizeof(struct sockaddr_in);
		ssize_t length;

		if ((length = recvfrom(server_socket, client_buf, UDP_BUFFER_CAPACITY, 0, (struct sockaddr *) &client_add,
		                       &client_add_size)) < 0) {
			printf("recvfrom() failed.\n");
			continue;
		}

		printf("Accept client <%s> on UDP Port <%d>\n", inet_ntoa(client_add.sin_addr), client_add.sin_port);
		printf("Received a DNS packet. Length: <%zi>\n", length);

		//开始解析DNS packet
		resolve_query_packet();

		//解析并回应
		resolve_and_response();
	}
#pragma clang diagnostic pop

	//关闭socket
	server_socket_close();
	return 0;
}

//清空程序内存中原来的记录，或是初始化这些变量
void clean() {
	pHeader = malloc(sizeof(struct DNS_Header));
	pQuery = malloc(sizeof(struct DNS_Query));
	rHeader = malloc(sizeof(struct DNS_Header));
	rAnswers = malloc(sizeof(struct DNS_Record) * 16); //需要预留足够大的内存
	rAuth = malloc(sizeof(struct DNS_Record) * 16);
	rAdd = malloc(sizeof(struct DNS_Record) * 16);
}

//设置服务器socket
void server_socket_setup() {
	//创建socket
	printf("Creating a socket...");
	if ((server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		printf("socket() failed.\n");
		exit(1);
	}
	printf("OK!\n");

	//设置地址结构体
	printf("Initializing socket address...");
	memset(&server_add, 0, sizeof(struct sockaddr_in));
	server_add.sin_family = AF_INET;
	server_add.sin_port = htons(DNS_SERVER_PORT);
	server_add.sin_addr.s_addr = inet_addr(DNS_SERVER_ADDRESS);
	printf("OK!\n");

	//绑定socket
	printf("Binding socket address...");
	if ((bind(server_socket, (struct sockaddr *) &server_add, sizeof(struct sockaddr_in))) < 0) {
		printf("bind() failed.\n");
		exit(1);
	}
	printf("OK!\n");
}

//关闭服务器socket
void server_socket_close() {
	printf("Closing the socket...");
	close(server_socket);
	printf("OK!\n");
}

//解析DNS packet //记录客户端查询请求
void resolve_query_packet() {
	printf("==================================================\n");
	size_t loc = 0;
	u_char *reader = client_buf;

	//Header
	pHeader = resolve_header(&loc, reader);
	reader += loc;

	pQuery = malloc(sizeof(struct DNS_Query));

	//Queries
	printf("<1> query.\n");
	pQuery = resolve_query(&loc, client_buf, reader);
	printf("==================================================\n");
}

//解析并回应
void resolve_and_response() {
	printf("Starting resolve...\n");
	rHeader = construct_header(pHeader->id, DNS_RESPONSE, pHeader->flags->rd, DNS_RCODE_NO_ERROR, 1, 0, 0, 0);

	//这里查询情况：完全匹配，无匹配
	int code = resolve_record(pQuery->name, pQuery->type);

	//完全匹配
	if (code > 0) {
		udp_response(rHeader, pQuery, rAnswers, rAuth, rAdd);
		return;
	} else { //无匹配
		rHeader->flags->rcode = DNS_RCODE_NAME_ERROR;
		udp_response(rHeader, pQuery, rAnswers, rAuth, rAdd);
		return;
	}
}

//查询本地记录 //A - IP //CNAME - 域名 //MX - 域名
int resolve_record(u_char *query_name, uint16_t type) {
	//查询本地
	printf("Finding <%s> for type <%s> in local file...\n", query_name, get_type_name(type));
	int local_code = resolve_file(DNS_FILE, query_name, type, 0);

	if (local_code > 0)
		return 1;

	//arpa server比较特殊，不会有NS记录，所以不会出现部分匹配的情况

	printf("Not found full name records. No such name. (RCODE=3)\n");
	return -1;
}

//查询文件记录
int resolve_file(char *filename, u_char *query_name, uint16_t type, int cache) {
	int num;
	struct DNS_Record **record = get_record(filename, &num, cache);

	for (int i = 0; i < num; i++) {
		if (!strcmp((const char *) record[i]->name, (const char *) query_name) && record[i]->type == type) { //名称和类型都相同
			if (type == DNS_TYPE_A || type == DNS_TYPE_CNAME || type == DNS_TYPE_PTR) { //只支持部分类型查询
				rAnswers[rHeader->answers++] = record[i];
			} else if (type == DNS_TYPE_MX) {
				rAnswers[rHeader->answers++] = record[i]; //将MX记录存入answers中
				for (int j = 0; j < num; j++) {
					if (!strcmp((const char *) record[j]->name, (const char *) read_data_name(record[i]->data + 2)) &&
					    record[j]->type == DNS_TYPE_A) {
						rAdd[rHeader->add_rr++] = record[j]; //将MX对应的A记录存入additional中
					}
				}
			}
		}
	}

	if (rHeader->answers > 0) { //本地有记录
		printf("Found <%hu> records.\n", rHeader->answers);
		return 1;
	}

	printf("Not found full name. Finding partial name...\n");

	//这里的状态，没有查找到完全相同域名的记录，开始查找域名后缀对应的NS记录
	//分解域名
	char **pch = malloc(MAX_NAME_LENGTH);
	int j = 0;
	char copy_name[MAX_NAME_LENGTH] = {0};
	memcpy(copy_name, query_name, strlen((const char *) query_name));
	pch[0] = strtok(copy_name, ".");
	while (pch[j] != NULL) {
		pch[++j] = strtok(NULL, ".");
	}
	//先查com 再google.com 再www.google.com
	int parts = 0;
	while (--j > -1) {
		parts++; //域名中有几部分
		char name[MAX_NAME_LENGTH] = {0};
		for (int m = 0; m < parts; m++) {
			strcat(name, pch[j + m]);
			strcat(name, ".");
		}
		name[strlen(name) - 1] = '\0'; //去掉最后的点
		printf("Finding partial name: <%s>...\n", name);
		for (int i = 0; i < num; i++) {
			if (!strcmp((const char *) record[i]->name, name) && record[i]->type == DNS_TYPE_NS) { //找到对应的NS记录
				printf("Found record. <%s> <%u> <%s> <%s> <%s>\n", record[i]->name, record[i]->ttl,
				       get_class_name(record[i]->class), get_type_name(record[i]->type),
				       read_data_name(record[i]->data));
				rAuth[rHeader->auth_rr++] = record[i]; //将NS记录存入authoritative中
				for (int k = 0; k < num; k++) {
					if (!strcmp((const char *) record[k]->name, (const char *) read_data_name(record[i]->data)) &&
					    record[k]->type == DNS_TYPE_A) {
						printf("Found record. <%s> <%u> <%s> <%s>\n", record[k]->name, record[k]->ttl,
						       get_class_name(record[k]->class), get_type_name(record[k]->type));
						rAdd[rHeader->add_rr++] = record[k]; //将NS对应的A记录存入additional中
					}
				}
			}
		}
	}

	if (rHeader->auth_rr > 0) {
		printf("Found <%hu> authoritative records.\n", rHeader->auth_rr);
		return 0;
	}

	return -1; //本地没有记录 且 没有NS记录
}

//回复记录
void udp_response(struct DNS_Header *header, struct DNS_Query *query, struct DNS_Record **answers,
                  struct DNS_Record **auth, struct DNS_Record **add) {
	bzero(client_buf, UDP_BUFFER_CAPACITY);

	printf("Constructing a DNS packet...");
	size_t loc = 0;

	struct DNS_Query **queries = malloc(sizeof(struct DNS_Query));
	queries[0] = query;

	loc = construct_dns_packet(loc, client_buf, header, queries, answers, auth, add);
	printf("OK!\n");

	printf("Sending a DNS packet...Length: <%zu>...", loc);
	sendto(server_socket, client_buf, loc, 0, (struct sockaddr *) &client_add, sizeof(client_add));
	printf("OK!\n");
}
