/*
 * DNS project header file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <memory.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#pragma pack(1) //强制让内存按 1 byte 对齐 //因为有内存对齐这个机制的存在，导致了一些结构体的大小比真实的大小大

typedef unsigned char u_char;

#define UDP_BUFFER_CAPACITY                     512
#define TCP_BUFFER_CAPACITY                     65536

#define MAX_NAME_LENGTH                         64

#define DNS_SERVER_0                            "127.1.1.1" //Local DNS Server
#define DNS_SERVER_1                            "127.2.2.1" //root-servers.net          Root DNS Server
#define DNS_SERVER_2                            "127.2.2.2" //in-addr-servers.arpa      in-addr ARPA DNS Server
#define DNS_SERVER_3                            "127.3.3.1" //a.tld-servers.net         TLD DNS Server A
#define DNS_SERVER_4                            "127.3.3.2" //b.tld-servers.net         TLD DNS Server B
#define DNS_SERVER_5                            "127.4.4.1" //a.second-servers.net      Second DNS Server A
#define DNS_SERVER_6                            "127.4.4.2" //b.second-servers.net      Second DNS Server B

#define DNS_SERVER_PORT                         53

#define DNS_DEFAULT_PREFERENCE                  5

#define DNS_TYPE_A                              1
#define DNS_TYPE_NS                             2
#define DNS_TYPE_CNAME                          5
#define DNS_TYPE_PTR                            12
#define DNS_TYPE_MX                             15

#define DNS_CLASS_IN                            1 //the Internet
#define DNS_CLASS_CS                            2 //the CSNET class
#define DNS_CLASS_CH                            3 //the CHAOS class
#define DNS_CLASS_HS                            4 //Hesiod [Dyer 87]

#define DNS_QUERY                               0
#define DNS_RESPONSE                            1

#define DNS_OPCODE_STANDARD                     0
#define DNS_OPCODE_INVERSE                      1
#define DNS_OPCODE_STATUS                       2

#define DNS_ITERATIVE                           0
#define DNS_RECURSIVE                           1

#define DNS_RCODE_NO_ERROR                      0
#define DNS_RCODE_FORMAT_ERROR                  1
#define DNS_RCODE_SERVER_FAILURE                2
#define DNS_RCODE_NAME_ERROR                    3 //No such name
#define DNS_RCODE_NOT_IMPLEMENTED               4
#define DNS_RCODE_REFUSED                       5

struct header_flags { //全部倒序排列 //比特序问题
	uint8_t rcode:4;
	uint8_t z:3;
	uint8_t ra:1;

	uint8_t rd:1;
	uint8_t tc:1;
	uint8_t aa:1;
	uint8_t opcode:4;
	uint8_t qr:1;
};

struct DNS_Header {
	uint16_t id;
	struct header_flags *flags;
	uint16_t queries;
	uint16_t answers;
	uint16_t auth_rr;
	uint16_t add_rr;
};

struct DNS_Query {
	u_char *name;
	uint16_t type;
	uint16_t class;
};

struct DNS_Record {
	u_char *name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t len;
	u_char *data; //此处存放的是原始数据，若有域名，格式为3www6google3com0
};

//转换查询域名的格式 www.google.com -> 3www6google3com0
void transform(u_char *query_name, u_char *hostname) {
	int loc = 0;
	char host[MAX_NAME_LENGTH] = {0};
	memcpy(host, hostname, strlen((const char *) hostname));
	strcat(host, ".");

	for (int i = 0; i < strlen(host); i++) {
		if (host[i] == '.') {
			*query_name++ = (u_char) (i - loc);
			for (; loc < i; loc++) {
				*query_name++ = (u_char) host[loc];
			}
			loc++;
		}
	}
	*query_name = 0; //3www6google3com0长度应为16，strlen()会输出15，忽略最后的0
}

//解决strlen不计算最后0的长度的问题
size_t sizeofname(u_char *query_name) {
	return strlen((const char *) query_name) + 1;
}

//读取record中data的域名
u_char *read_data_name(u_char *data) {
	u_char *name = malloc(MAX_NAME_LENGTH);
	memcpy(name, data, sizeofname(data));

	//3www6google3com0 -> www.google.com
	int i = 0;
	for (; i < strlen((const char *) name); i++) {
		int num = name[i];
		for (int j = 0; j < num; j++) {
			name[i] = name[i + 1];
			i++;
		}
		name[i] = '.';
	}
	name[i - 1] = '\0'; //把最后多余的点去掉
	return name;
}

//读取回应中的域名
u_char *read_name(int *loc, u_char *buf, u_char *reader) {
	u_char *name = malloc(MAX_NAME_LENGTH);
	int num = 0, jumped = 0;

	*loc = 0;

	while (*reader != 0x00) { // 0 表示读取到最后一位，该结束了
//		if (*reader < 0xC0) { // 0xC0 域名 偏移 //启用中文域名之后就与现有的偏移判断冲突，只能取消判断，这也意味着，这套程序不能和互联网DNS服务正常兼容
		name[num++] = *reader;
		reader++;
//		} else {
//			int offset = (*reader - 0xC0) * 0x0100 + *(reader + 1); //计算偏移量
//			reader = buf + offset; //跳转偏移位置
//			jumped = 1;
//		}

		if (jumped == 0)
			(*loc)++;
	}
	name[num] = '\0'; //最后字符串结个尾

	if (jumped == 1)
		*loc += 2; //加上sizeof(offset) 2byte
	else
		(*loc)++; //加上包中域名最后的0的长度

	return read_data_name(name);
}

//1.2.4.8 -> 8.4.2.1.in-addr.arpa
char *ip2arpa(char *ip) {
	char *suffix = "in-addr.arpa";

	char *result = malloc(MAX_NAME_LENGTH);
	bzero(result, MAX_NAME_LENGTH);
	char temp[4][4] = {0};

	char string[MAX_NAME_LENGTH] = {0};
	memcpy(string, ip, strlen(ip));

	char *token = strtok(string, ".");
	for (int i = 0; i < 4; i++) {
		memcpy(temp[3 - i], token, strlen(token));
		strcat(temp[3 - i], ".");
		token = strtok(NULL, ".");
	}
	for (int i = 0; i < 4; i++) {
		strcat(result, temp[i]); //8.4.2.1.
	}
	strcat(result, suffix);

	return result;
}

//构造Header
struct DNS_Header *
construct_header(uint16_t id, uint8_t qr, uint8_t rd, uint8_t rcode, uint16_t queries, uint16_t answers,
                 uint16_t auth_rr, uint16_t add_rr) {
	struct DNS_Header *pHeader = malloc(sizeof(struct DNS_Header));

	if (id)
		pHeader->id = id;
	else
		pHeader->id = (uint16_t) getpid(); //getpid()的作用是获得当前进程的ID，在这里的作用只是用作随机数

	pHeader->flags = malloc(sizeof(struct header_flags));
	pHeader->flags->qr = qr;
	pHeader->flags->opcode = DNS_OPCODE_STANDARD;
	pHeader->flags->aa = 0;
	pHeader->flags->tc = 0;
	pHeader->flags->rd = rd; //0迭代 1递归
	pHeader->flags->ra = 1; //递归的支持很简单
	pHeader->flags->z = 0;
	pHeader->flags->rcode = rcode;

	pHeader->queries = queries;
	pHeader->answers = answers;
	pHeader->auth_rr = auth_rr;
	pHeader->add_rr = add_rr;

	return pHeader;
}

//将Records写入buf
size_t construct_rr(size_t loc, u_char *buf, struct DNS_Record *pRecord) {
	u_char *name = pRecord->name;
	uint16_t type = pRecord->type;
	uint16_t class = pRecord->class;
	uint32_t ttl = pRecord->ttl;
	uint16_t len = pRecord->len;
	u_char *data = pRecord->data;

	//Query Name
	u_char *query_name = &buf[loc];
	transform(query_name, name); //转换域名
	loc += sizeofname(query_name);

	//Type
	type = htons(type);
	memcpy(&buf[loc], &type, sizeof(type));
	loc += sizeof(type);

	//Class
	class = htons(class);
	memcpy(&buf[loc], &class, sizeof(class));
	loc += sizeof(class);

	//TTL
	ttl = htonl(ttl);
	memcpy(&buf[loc], &ttl, sizeof(ttl));
	loc += sizeof(ttl);

	//Length
	len = htons(len);
	memcpy(&buf[loc], &len, sizeof(len));
	loc += sizeof(len);

	//Data
	memcpy(&buf[loc], data, pRecord->len);
	loc += pRecord->len;

	return loc;
}

//构造DNS packet //兼具query和response
size_t construct_dns_packet(size_t loc, u_char *buf, struct DNS_Header *pHeader, struct DNS_Query **pQueries,
                            struct DNS_Record **pAnswers, struct DNS_Record **pAuth, struct DNS_Record **pAdd) {
	//----------HEADER----------

	//Transaction ID
	uint16_t id = htons(pHeader->id);
	printf("header->id: <0x%04x>", pHeader->id);
	memcpy(&buf[loc], &id, sizeof(id));
	loc += sizeof(id);

	//Flags
	uint16_t flags;
	memcpy(&flags, pHeader->flags, sizeof(*(pHeader->flags)));
	flags = htons(flags);
	memcpy(&buf[loc], &flags, sizeof(flags));
	loc += sizeof(flags);

	//Number of queries in packet
	uint16_t queries = htons(pHeader->queries);
	memcpy(&buf[loc], &queries, sizeof(queries));
	loc += sizeof(queries);

	//Number of answers in packet
	uint16_t answers = htons(pHeader->answers);
	memcpy(&buf[loc], &answers, sizeof(answers));
	loc += sizeof(answers);

	//Number of authoritative records in packet
	uint16_t auth_rr = htons(pHeader->auth_rr);
	memcpy(&buf[loc], &auth_rr, sizeof(auth_rr));
	loc += sizeof(auth_rr);

	//Number of additional records in packet
	uint16_t add_rr = htons(pHeader->add_rr);
	memcpy(&buf[loc], &add_rr, sizeof(add_rr));
	loc += sizeof(add_rr);

	//----------QUERIES----------

	for (int i = 0; i < pHeader->queries; i++) {
		u_char *name = pQueries[i]->name;
		uint16_t type = pQueries[i]->type;
		uint16_t class = pQueries[i]->class;

		//Query Name
		u_char *query_name = &buf[loc];
		transform(query_name, name); //转换域名
		loc += sizeofname(query_name);

		//Query Type
		type = htons(type);
		memcpy(&buf[loc], &type, sizeof(type));
		loc += sizeof(type);

		//Query Class
		class = htons(class);
		memcpy(&buf[loc], &class, sizeof(class));
		loc += sizeof(class);
	}

	//----------ANSWERS----------

	for (int i = 0; i < pHeader->answers; i++)
		loc = construct_rr(loc, buf, pAnswers[i]);

	//----------AUTHORITATIVE----------

	for (int i = 0; i < pHeader->auth_rr; i++)
		loc = construct_rr(loc, buf, pAuth[i]);

	//----------ADDITIONAL----------

	for (int i = 0; i < pHeader->add_rr; i++)
		loc = construct_rr(loc, buf, pAdd[i]);

	//返回DNS包的长度
	return loc;
}

//得到类型名称
char *get_type_name(uint16_t type) {
	switch (type) {
		case DNS_TYPE_A:
			return "A";
		case DNS_TYPE_NS:
			return "NS";
		case DNS_TYPE_CNAME:
			return "CNAME";
		case DNS_TYPE_PTR:
			return "PTR";
		case DNS_TYPE_MX:
			return "MX";
		default:
			return "Unknown";
	}
}

//得到类别名称
char *get_class_name(uint16_t class) {
	switch (class) {
		case DNS_CLASS_IN:
			return "IN";
		default:
			return "Unknown";
	}
}

//解析Header
struct DNS_Header *resolve_header(size_t *loc, u_char *reader) {
	*loc = 0;
	struct DNS_Header *pHeader = malloc(sizeof(struct DNS_Header));

	//Transaction ID
	memcpy(&pHeader->id, reader, sizeof(pHeader->id));
	pHeader->id = ntohs(pHeader->id);
	reader += sizeof(pHeader->id);
	*loc += sizeof(pHeader->id);
	printf("Transaction ID: <0x%04x> ", pHeader->id);

	//Flags
	uint16_t flags;
	memcpy(&flags, reader, sizeof(flags));
	flags = ntohs(flags);
	pHeader->flags = malloc(sizeof(*(pHeader->flags)));
	memcpy(pHeader->flags, &flags, sizeof(*(pHeader->flags)));
	reader += sizeof(*(pHeader->flags));
	*loc += sizeof(*(pHeader->flags));
	printf("Flags: <0x%04x> ", flags);

	//Queries
	memcpy(&pHeader->queries, reader, sizeof(pHeader->queries));
	pHeader->queries = ntohs(pHeader->queries);
	reader += sizeof(pHeader->queries);
	*loc += sizeof(pHeader->queries);

	//Answers
	memcpy(&pHeader->answers, reader, sizeof(pHeader->answers));
	pHeader->answers = ntohs(pHeader->answers);
	reader += sizeof(pHeader->answers);
	*loc += sizeof(pHeader->answers);

	//Authoritative
	memcpy(&pHeader->auth_rr, reader, sizeof(pHeader->auth_rr));
	pHeader->auth_rr = ntohs(pHeader->auth_rr);
	reader += sizeof(pHeader->auth_rr);
	*loc += sizeof(pHeader->auth_rr);

	//Additional
	memcpy(&pHeader->add_rr, reader, sizeof(pHeader->add_rr));
	pHeader->add_rr = ntohs(pHeader->add_rr);
	reader += sizeof(pHeader->add_rr);
	*loc += sizeof(pHeader->add_rr);

	//----------FLAGS----------

	if (pHeader->flags->qr)
		printf("Response packet. ");
	else
		printf("Query packet. ");

	if (pHeader->flags->opcode == DNS_OPCODE_STANDARD)
		printf("Standard query. ");
	else if (pHeader->flags->opcode == DNS_OPCODE_INVERSE)
		printf("Inverse query. ");
	else if (pHeader->flags->opcode == DNS_OPCODE_STATUS)
		printf("Server status request. ");

	if (pHeader->flags->qr) { //只在解析回应包时显示这些信息，下同
		if (pHeader->flags->aa)
			printf("Authoritative response. ");
		else
			printf("Non-authoritative response. ");
	}

	if (pHeader->flags->rd)
		printf("Recursive query. ");
	else
		printf("Iterative query. ");

	if (pHeader->flags->qr) {
		if (pHeader->flags->ra)
			printf("Server can do recursive queries. ");
		else
			printf("Server cannot do recursive queries. ");

		if (pHeader->flags->rcode == DNS_RCODE_NO_ERROR)
			printf("No error. ");
		else if (pHeader->flags->rcode == DNS_RCODE_FORMAT_ERROR)
			printf("Format error. ");
		else if (pHeader->flags->rcode == DNS_RCODE_SERVER_FAILURE)
			printf("Server failure. ");
		else if (pHeader->flags->rcode == DNS_RCODE_NAME_ERROR)
			printf("No such name. ");
		else if (pHeader->flags->rcode == DNS_RCODE_NOT_IMPLEMENTED)
			printf("Server not implemented. ");
		else if (pHeader->flags->rcode == DNS_RCODE_REFUSED)
			printf("Server refused. ");
	}

	printf("\n");

	return pHeader;
}

//解析Query
struct DNS_Query *resolve_query(size_t *loc, u_char *buf, u_char *reader) {
	*loc = 0;
	int temp_loc = 0;
	struct DNS_Query *pQuery = malloc(sizeof(struct DNS_Query));

	//Query Name
	pQuery->name = read_name(&temp_loc, buf, reader);
	reader += temp_loc;
	*loc += temp_loc;
	printf("Name: <%s> ", pQuery->name);

	//Query Type
	memcpy(&pQuery->type, reader, sizeof(pQuery->type));
	pQuery->type = ntohs(pQuery->type);
	reader += sizeof(pQuery->type);
	*loc += sizeof(pQuery->type);
	printf("Type: <%s> ", get_type_name(pQuery->type));

	//Query Class
	memcpy(&pQuery->class, reader, sizeof(pQuery->class));
	pQuery->class = ntohs(pQuery->class);
	reader += sizeof(pQuery->class);
	*loc += sizeof(pQuery->class);
	printf("Class: <%s> ", get_class_name(pQuery->class));

	printf("\n");

	return pQuery;
}

//解析Resource Record //Answer + Authoritative + Additional
struct DNS_Record *resolve_rr(size_t *loc, u_char *buf, u_char *reader) {
	*loc = 0;
	int temp_loc = 0;
	struct DNS_Record *pRecord = malloc(sizeof(struct DNS_Record));

	//Record Name
	pRecord->name = read_name(&temp_loc, buf, reader);
	reader += temp_loc;
	*loc += temp_loc;
	printf("Name: <%s> ", pRecord->name);

	//Record Type
	memcpy(&pRecord->type, reader, sizeof(pRecord->type));
	pRecord->type = ntohs(pRecord->type);
	reader += sizeof(pRecord->type);
	*loc += sizeof(pRecord->type);
	printf("Type: <%s> ", get_type_name(pRecord->type));

	//Record Class
	memcpy(&pRecord->class, reader, sizeof(pRecord->class));
	pRecord->class = ntohs(pRecord->class);
	reader += sizeof(pRecord->class);
	*loc += sizeof(pRecord->class);
	printf("Class: <%s> ", get_class_name(pRecord->class));

	//Record TTL
	memcpy(&pRecord->ttl, reader, sizeof(pRecord->ttl));
	pRecord->ttl = ntohl(pRecord->ttl);
	reader += sizeof(pRecord->ttl);
	*loc += sizeof(pRecord->ttl);
	printf("Time to live: <%u> ", pRecord->ttl);

	//Record Length
	memcpy(&pRecord->len, reader, sizeof(pRecord->len));
	pRecord->len = ntohs(pRecord->len);
	reader += sizeof(pRecord->len);
	*loc += sizeof(pRecord->len);
	printf("Data length: <%hu> ", pRecord->len);

	//Record Data
	u_char *_data = malloc(pRecord->len);
	bzero(_data, pRecord->len);
	memcpy(_data, reader, pRecord->len);
	pRecord->data = _data;

	//----------DATA----------

	if (pRecord->type == DNS_TYPE_A) {
		struct sockaddr_in t;
		memcpy(&t.sin_addr, pRecord->data, sizeof(struct in_addr));
		printf("Address: <%s> ", inet_ntoa(t.sin_addr));
	} else if (pRecord->type == DNS_TYPE_NS) {
		printf("Name Server: <%s> ", read_name(&temp_loc, buf, reader));
	} else if (pRecord->type == DNS_TYPE_CNAME) {
		printf("CNAME: <%s> ", read_name(&temp_loc, buf, reader));
	} else if (pRecord->type == DNS_TYPE_PTR) {
		printf("Domain Name: <%s> ", read_name(&temp_loc, buf, reader));
	} else if (pRecord->type == DNS_TYPE_MX) {
		uint16_t preference;
		memcpy(&preference, pRecord->data, sizeof(preference));
		reader += sizeof(preference);
		printf("Preference: <%hu> Mail Exchange: <%s> ", ntohs(preference), read_name(&temp_loc, buf, reader));
		reader -= sizeof(preference);
	}
	printf("\n");
	reader += pRecord->len;
	*loc += pRecord->len;

	return pRecord;
}

//得到类型数值
uint16_t get_type_num(char *type) {
	if (!strcmp(type, "A"))
		return DNS_TYPE_A;
	else if (!strcmp(type, "NS"))
		return DNS_TYPE_NS;
	else if (!strcmp(type, "CNAME"))
		return DNS_TYPE_CNAME;
	else if (!strcmp(type, "PTR"))
		return DNS_TYPE_PTR;
	else if (!strcmp(type, "MX"))
		return DNS_TYPE_MX;
	else
		return 0;
}

//得到类别数值
uint16_t get_class_num(char *class) {
	if (!strcmp(class, "IN"))
		return DNS_CLASS_IN;
	else if (!strcmp(class, "CS"))
		return DNS_CLASS_CS;
	else if (!strcmp(class, "CH"))
		return DNS_CLASS_CH;
	else if (!strcmp(class, "HS"))
		return DNS_CLASS_HS;
	else
		return 0;
}

//从文件中读取记录
struct DNS_Record **get_record(char *filename, int *num, int is_cache) {
	char buff[MAX_NAME_LENGTH * 4] = {0};

	FILE *file = fopen(filename, "r");

	struct DNS_Record **record = malloc(sizeof(struct DNS_Record) * 128); //这里需要设置足够大的内存才能正常运行

	int i = 0;

	while (fgets(buff, sizeof(buff), file) != NULL) {

		if (buff[0] == '#' || strlen(buff) < 3) //跳过注释行和空行  \r\n换行算两个字符
			continue;

		u_char *name = malloc(MAX_NAME_LENGTH);
		bzero(name, MAX_NAME_LENGTH);
		int ttl;
		long int cache;
		char *class = malloc(MAX_NAME_LENGTH);
		bzero(class, MAX_NAME_LENGTH);
		char *type = malloc(MAX_NAME_LENGTH);
		bzero(type, MAX_NAME_LENGTH);
		u_char *data = malloc(MAX_NAME_LENGTH);
		bzero(data, MAX_NAME_LENGTH);

		if (is_cache) {
			sscanf(buff, "%s %d %li %s %s %s", name, &ttl, &cache, class, type, data); // NOLINT
			time_t now;
			time(&now);
			if (cache < now) {
				printf("Ignore an expired cache.\n");
				continue;
			}
		} else
			sscanf(buff, "%s %d %s %s %s", name, &ttl, class, type, data); // NOLINT

		record[i] = malloc(sizeof(struct DNS_Record));

		record[i]->name = name;
		record[i]->type = get_type_num(type);
		record[i]->class = get_class_num(class);
		record[i]->ttl = (uint32_t) ttl;

		if (record[i]->type == DNS_TYPE_A) {
			record[i]->len = sizeof(struct in_addr); //4
			struct sockaddr_in t;
			t.sin_addr.s_addr = inet_addr((const char *) data);
			u_char *_data = malloc(record[i]->len);
			memcpy(_data, &t.sin_addr, sizeof(struct in_addr));
			record[i]->data = _data;
		} else if (record[i]->type == DNS_TYPE_NS || record[i]->type == DNS_TYPE_CNAME ||
		           record[i]->type == DNS_TYPE_PTR) {
			u_char *_data = malloc(MAX_NAME_LENGTH);
			bzero(_data, MAX_NAME_LENGTH);
			transform(_data, data);
			record[i]->len = (uint16_t) sizeofname(_data);
			record[i]->data = _data;
		} else if (record[i]->type == DNS_TYPE_MX) {
			uint16_t preference = htons(DNS_DEFAULT_PREFERENCE);

			u_char *data_name = malloc(MAX_NAME_LENGTH);
			bzero(data_name, MAX_NAME_LENGTH);
			transform(data_name, data);

			record[i]->len = sizeof(preference) + sizeofname(data_name);

			u_char *_data = malloc(MAX_NAME_LENGTH);
			memcpy(_data, &preference, sizeof(preference));
			memcpy(_data + sizeof(preference), data_name, sizeofname(data_name));
			record[i]->data = _data;
		} else {
			record[i]->len = (uint16_t) strlen(buff);
			record[i]->data = data;
		}
		i++;
	}

	fclose(file);

	*num = i;

	return record;
}

//保存record到指定文件指针中
void save_record(FILE *file, struct DNS_Record *record) {
	size_t name_length = 48, time_length = 12, cache_length = 16, class_length = 8, type_length = 8; //文件中每个字段的长度，用来对齐

	fprintf(file, "%s", record->name);
	for (int j = 0; j < name_length - strlen((const char *) record->name); j++)
		fprintf(file, " "); //补足空格，用以对齐

	char time_str[time_length];
	bzero(time_str, time_length);
	sprintf(time_str, "%u", record->ttl);
	fprintf(file, "%s", time_str);
	for (int j = 0; j < time_length - strlen(time_str); j++)
		fprintf(file, " ");

	//cache
	time_t now;
	time(&now);
	time_t cache = now + record->ttl;
	char cache_str[cache_length];
	bzero(cache_str, cache_length);
	sprintf(cache_str, "%li", cache);
	fprintf(file, "%s", cache_str);
	for (int j = 0; j < cache_length - strlen(cache_str); j++)
		fprintf(file, " ");

	fprintf(file, "%s", get_class_name(record->class));
	for (int j = 0; j < class_length - strlen(get_class_name(record->class)); j++)
		fprintf(file, " ");

	fprintf(file, "%s", get_type_name(record->type));
	for (int j = 0; j < type_length - strlen(get_type_name(record->type)); j++)
		fprintf(file, " ");

	if (record->type == DNS_TYPE_A) {
		struct sockaddr_in t;
		memcpy(&t.sin_addr, record->data, sizeof(struct in_addr));
		fprintf(file, "%s", inet_ntoa(t.sin_addr));
	} else if (record->type == DNS_TYPE_NS || record->type == DNS_TYPE_CNAME || record->type == DNS_TYPE_PTR) {
		fprintf(file, "%s", read_data_name(record->data));
	} else if (record->type == DNS_TYPE_MX) {
		fprintf(file, "%s", read_data_name(record->data + 2));
	} else {
		fprintf(file, "%s", record->data);
	}

	fprintf(file, "\n");
}

//保存查询记录到缓存中
void save_cache(char *filename, struct DNS_Header *header, struct DNS_Record **answer, struct DNS_Record **auth,
                struct DNS_Record **add) {
	printf("Saving records to cache...");
	FILE *file = fopen(filename, "a+");

	for (int i = 0; i < header->answers; i++)
		save_record(file, answer[i]);

	for (int i = 0; i < header->auth_rr; i++)
		save_record(file, auth[i]);

	for (int i = 0; i < header->add_rr; i++)
		save_record(file, add[i]);

	fclose(file);
	printf("OK!\n");
}
