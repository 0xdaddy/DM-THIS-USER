#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ConsoleApi.h>
#include <synchapi.h>
#include <sysinfoapi.h>
#include <rpcdce.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment (lib, "crypt32");
#pragma comment(lib, "rpcrt4.lib")
#else
#include <sys/socket.h>
#include<arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <uuid/uuid.h>
#endif

#include <openssl/ssl.h>
#include <json-c/json.h>
#include <curl/curl.h>


#define BLK "\x1b[0;30m"
#define RED "\x1b[0;31m"
#define GRN "\x1b[0;32m"
#define YEL "\x1b[0;33m"
#define BLU "\x1b[0;34m"
#define MAG "\x1b[0;35m"
#define CYN "\x1b[0;36m"
#define WHT "\x1b[0;37m"
#define reset "\x1b[0m"

#define sslPORT 443

#define JObject struct json_object *
#define JNewObject json_object_new_object() 
#define JAddObject(obj,key,val) json_object_object_add(obj,key,val)
#define JOtoString(obj) json_object_to_json_string(obj)
#define JOget(obj, key) json_object_object_get(obj,key)
#define JSget(obj) json_object_get_string(obj)

#define initSSL() SSL_load_error_strings(); SSL_library_init(); 

#define array_size(arr) sizeof(arr) / sizeof(arr[0]) + 1

#define _1KB 1400

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef _WIN32
typedef unsigned int SOCKET;
#define INVALID_SOCKET  (SOCKET)(~0)
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif

#ifdef _WIN32
#define sleep(x) Sleep(x * 1000)
#endif

typedef int BOOL;

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


typedef struct Cookies
{
    char* sessionid;
    char* ds_user_id;
    char* csrftoken;
    char* mid;
    char* cookie_header;
}COOKIES;

typedef struct data_login
{
#ifdef _WIN32
    unsigned char* uuid;
#else
    char* uuid;
#endif 
    char* password;
    char* username;
}DATA_LOGIN;

typedef struct {
    struct sockaddr_in server;
    SOCKET s;
    SSL_CTX* ssl_ctx;
    SSL* ssl_sock;
    const char* IP;
}sock_data;

typedef struct data_dm {

    char* username;
    const char* pk;
    char* message;

}DATA_DM;

enum {
    WR = 0,
    ER = 1,
    GD = 2,
#ifdef IN
#undef IN
#endif
    IN = 3
};

char** split(char* str, char* delim);
char* enc_passw(char* passw);
char* _sign(int sign);
SOCKET createsocket();
void clear();
char* recv_res(SSL** ssl_sock);
char* remove_word(char* str, char* word_to_remove);
char* create_uuid();
char* gzip(char* str);
char* get_cookie_value_by_key(char* res, char* key);
char* hostname_to_ip(const char* hostname);
char* payload_encode(const char* _data);
void free_array(void* __f, size_t size_alloc);
char* strrpc(const char* instring, const char* old_part, const char* new_part);
SSL* ssl_connect(sock_data* sk_dt);
void free_sock_data(sock_data* sk_dt);
void free_char(char* str);
const char* getid(char* username, COOKIES* cok, char* headers, SSL** ssl_sock);
char* timestamp_in_char();
char* get_status_code(char* res);
#define CLS clear();
#ifndef ZeroMemory
#define ZeroMemory(__f, size_alloc) free_array(__f, size_alloc)
#endif
#define ZeroChar(str) free_char(str)
#define SSLconnect() ssl_connect(&sk_dt);
#define SSLreconnect() free_sock_data(&sk_dt);\
                       ssl_connect(&sk_dt);
#define fflush_scanf while ((getchar()) != '\n')
int main(void) {
    CLS
        sock_data sk_dt;
    COOKIES cok;
    DATA_LOGIN dta;
#ifdef _WIN32
    sk_dt.IP = "157.240.196.63";
#else
    sk_dt.IP = hostname_to_ip("i.instagram.com");
#endif
#ifdef _WIN32
    SetConsoleTitleW(L"instagram tool | by insta 0xdevil");
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
#endif


    SSLconnect();

    char HEADERS[1024] = "Host: i.instagram.com\r\n"
        "user-agent: Instagram 155.0.0.37.107 Android (20/5.6; 320dpi; 1080x1260; HUAWEI; VIVO-Z9QXB; zqjk; mm3693; en_US)\r\n"
        "Connection: Close\r\n"
        "Accept: */*\r\n";
    char METHOD[1024] = "GET /api/v1/accounts/login/ HTTP/1.1\r\n";
    strcat(METHOD, HEADERS);
    strcat(METHOD, "\r\n");
    if (SSL_write(sk_dt.ssl_sock, METHOD, strlen(METHOD)) < 0) {
        printf("%sError while send payload to instagram !\n", _sign(ER));
#ifdef _WIN32
        system("pause");
#endif
        return EXIT_FAILURE;
    }

    char* res = recv_res(&sk_dt.ssl_sock);



    if (strstr(res, "csrftoken") != NULL) {
        cok.csrftoken = get_cookie_value_by_key(res, "csrftoken");
        cok.mid = get_cookie_value_by_key(res, "mid");
    }
    else {
        printf("%sError not found csrftoken\n%sit\'s could be 429/too many requests !\n", _sign(ER), _sign(WR));
        printf("%sstatus code: %s\n", _sign(IN), get_status_code(res));
        exit(0);
    }
    ZeroChar(METHOD);
    CLS
#ifdef _WIN32
        
    _getting_info:
    
#else
        __asm__(
            "_getting_info:"
        );
#endif

    dta.username = calloc(512, sizeof(char*));
    dta.password = calloc(512, sizeof(char*));
    printf("%sgetting info from user .\n\n", _sign(WR));
    printf("%sUsername: ", _sign(IN));
    scanf("%s", dta.username);
    printf("%sPassword: ", _sign(IN));
    fflush(stdout);
    fflush_scanf;
    fgets(dta.password, 512, stdin);
    printf("%sYour info ----------\n", _sign(IN));
    printf("USERNAME=%s\n", dta.username);
    printf("PASSWORD=%s\n", dta.password);
    printf("is it ok[y/n]");
    char ansr[1];
    scanf("%s", &ansr);
    char c = ansr[0];
    if ((char)c != 'y' && (char)c != 'Y') {
        CLS
#ifdef _WIN32
        
        goto _getting_info;
        
#else
            __asm__(
                "jmp _getting_info"
            );
#endif
    }
    int size = strlen(dta.password);
    dta.password[size - 1] = '\0';
    dta.uuid = create_uuid();


    JObject _json_data = JNewObject;
    JAddObject(_json_data, "jazoest", json_object_new_string("22713"));
    JAddObject(_json_data, "phone_id", json_object_new_string(dta.uuid));
    JAddObject(_json_data, "_csrftoken", json_object_new_string(cok.csrftoken));
    JAddObject(_json_data, "username", json_object_new_string(dta.username));
    JAddObject(_json_data, "enc_password", json_object_new_string(enc_passw(dta.password)));
    JAddObject(_json_data, "adid", json_object_new_string(dta.uuid));
    JAddObject(_json_data, "device_id", json_object_new_string(dta.uuid));
    JAddObject(_json_data, "guid", json_object_new_string(dta.uuid));
    JAddObject(_json_data, "google_tokens", json_object_new_string("[]"));
    JAddObject(_json_data, "login_attempt_count", json_object_new_string("0"));


    char payload[1024];
    char _signed[1024];
    char* encode_payload = payload_encode(JOtoString(_json_data));
    sprintf(_signed, "SIGNATURE.%s", encode_payload);
    sprintf(payload, "signed_body=%s", _signed);

    char  mid[124];
    sprintf(mid, "x-mid: %s\r\n", cok.mid);

    char contect_length[126];
    sprintf(contect_length, "Content-Length: %d\r\n", strlen(payload));

    strcat(METHOD, "POST /api/v1/accounts/login/ HTTP/1.1\r\n");
    strcat(METHOD, HEADERS);
    strcat(METHOD, "content-type: application/x-www-form-urlencoded; charset=UTF-8\r\n");
    strcat(METHOD, mid);
    strcat(METHOD, contect_length);
    strcat(METHOD, "\r\n");
    strcat(METHOD, payload);


    SSLreconnect();
    CLS
        printf("%sAttempt to login !\n", _sign(IN));
    if (SSL_write(sk_dt.ssl_sock, METHOD, strlen(METHOD)) < 0) {

    }
    res = recv_res(&sk_dt.ssl_sock);
    char* content = strstr(res, "\r\n\r\n");
    if (content != NULL) {
        content += 4;
    }
    else {
        content = res;
    }
    if (strstr(res, "sessionid") != NULL) {
        ZeroChar(ansr);
        ZeroChar(METHOD);
        ZeroChar(payload);
        ZeroChar(contect_length);
        ZeroChar(mid);
        free(dta.username);
        free(dta.password);
#ifndef _WIN32
        free(encode_payload);
#endif
        cok.sessionid = get_cookie_value_by_key(res, "sessionid");
        cok.ds_user_id = get_cookie_value_by_key(res, "ds_user_id");
        char cokhead[512];
        sprintf(cokhead, "Cookie: csrftoken=%s;mid=%s;ds_user_id=%s;sessionid=%s;\r\n", cok.csrftoken, cok.mid, cok.ds_user_id, cok.sessionid);
        cok.cookie_header = cokhead;
        printf("%sLogged In\n", _sign(GD));
        printf("%sSessionID: %s\n\n", _sign(WR), cok.sessionid);
        DATA_DM dta_dm;
        dta_dm.username = calloc(512, sizeof(char*));
        dta_dm.message = calloc(512, sizeof(char*));
        printf("%sUser to dm: ", _sign(IN));
        scanf("%s", dta_dm.username);
        SSLreconnect();
        dta_dm.pk = getid(dta_dm.username, &cok, HEADERS, &sk_dt.ssl_sock);
        printf("%sMessage:", _sign(IN));
        fflush(stdout);
        fflush_scanf;
        fgets(dta_dm.message, 512, stdin);

        sprintf(payload, "text=%s&_uuid=%s&_csrftoken=missing&recipient_users=[[%s]]&_uid=%s&action=send_item&client_context=%s", dta_dm.message, dta.uuid, dta_dm.pk, dta.uuid, timestamp_in_char());
        encode_payload = payload_encode(payload);
        sprintf(contect_length, "Content-Length: %d\r\n", strlen(encode_payload));
        strcat(METHOD, "POST /api/v1/direct_v2/threads/broadcast/text/ HTTP/1.1\r\n");
        sprintf(mid, "x-mid: %s\r\n", cok.mid);
        strcat(METHOD, HEADERS);
        strcat(METHOD, cok.cookie_header);
        strcat(METHOD, mid);
        strcat(METHOD, "content-type: application/x-www-form-urlencoded; charset=UTF-8\r\n");
        strcat(METHOD, contect_length);
        strcat(METHOD, "\r\n");
        strcat(METHOD, encode_payload);
        SSLreconnect();
        if (SSL_write(sk_dt.ssl_sock, METHOD, strlen(METHOD)) < 0) {

        }
        res = recv_res(&sk_dt.ssl_sock);
    }
    else {
        ZeroChar(ansr);
        ZeroChar(METHOD);
        ZeroChar(payload);
        ZeroChar(contect_length);
        ZeroChar(mid);
        free(dta.username);
        free(dta.password);
#ifndef _WIN32
        free(encode_payload);
#endif
        printf("%slogin err !\n", _sign(ER));
        printf("%sWanna try again[y/n]?", _sign(IN));
        scanf("%s", &ansr);
        c = ansr[0];
        if ((char)c != 'n' && (char)c != 'N') {
            CLS
#ifdef _WIN32
            
                goto _getting_info;
            
#else
                __asm__(
                    "jmp _getting_info"
                );
#endif
        }
        printf("%sExit", _sign(ER));
#ifdef _WIN32
        system("pause");
#endif
    }
    return EXIT_SUCCESS;
}


char* strrpc(const char* instring, const char* old_part, const char* new_part) {
#ifndef EXPECTED_REPLACEMENTS
#define EXPECTED_REPLACEMENTS 100
#endif

    if (!instring || !old_part || !new_part)
    {
        return (char*)NULL;
    }

    size_t instring_len = strlen(instring);
    size_t new_len = strlen(new_part);
    size_t old_len = strlen(old_part);
    if (instring_len < old_len || old_len == 0)
    {
        return (char*)NULL;
    }

    const char* in = instring;
    const char* found = NULL;
    size_t count = 0;
    size_t out = 0;
    size_t ax = 0;
    char* outstring = NULL;

    if (new_len > old_len)
    {
        size_t Diff = EXPECTED_REPLACEMENTS * (new_len - old_len);
        size_t outstring_len = instring_len + Diff;
        outstring = (char*)malloc(outstring_len);
        if (!outstring) {
            return (char*)NULL;
        }
        while ((found = strstr(in, old_part)) != NULL)
        {
            if (count == EXPECTED_REPLACEMENTS)
            {
                outstring_len += Diff;
                if ((outstring = realloc(outstring, outstring_len)) == NULL)
                {
                    return (char*)NULL;
                }
                count = 0;
            }
            ax = found - in;
            strncpy(outstring + out, in, ax);
            out += ax;
            strncpy(outstring + out, new_part, new_len);
            out += new_len;
            in = found + old_len;
            count++;
        }
    }
    else
    {
        outstring = (char*)malloc(instring_len);
        if (!outstring) {
            return (char*)NULL;
        }
        while ((found = strstr(in, old_part)) != NULL)
        {
            ax = found - in;
            strncpy(outstring + out, in, ax);
            out += ax;
            strncpy(outstring + out, new_part, new_len);
            out += new_len;
            in = found + old_len;
        }
    }
    ax = (instring + instring_len) - in;
    strncpy(outstring + out, in, ax);
    out += ax;
    outstring[out] = '\0';

    return outstring;
}

char** split(char* str, char* delim)
{
#ifdef _WIN32
#define strdup(x) _strdup(x)
#endif  
    char* s = strdup(str);

    if (strtok(s, delim) == 0)

        return NULL;

    int nw = 1;

    while (strtok(NULL, delim) != 0) {
        nw += 1;
    }

    strcpy(s, str);

    char** v = malloc((nw + 1) * sizeof(char*));
    int i;

    v[0] = strdup(strtok(s, delim));

    for (i = 1; i != nw; ++i) {
        v[i] = strdup(strtok(NULL, delim));
    }

    v[i] = NULL;

    free(s);

    return v;
}


SOCKET createsocket() {
    SOCKET s;
#ifdef _WIN32

    WSADATA wsa;
    struct sockaddr_in server;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        return INVALID_SOCKET;
    }
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        return INVALID_SOCKET;
    }

#else
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        return  INVALID_SOCKET;
    }
#endif
    return s;
}


char* timestamp_in_char() {
#ifdef _WIN32
    char* timestamp = calloc(50, sizeof(char));
    SYSTEMTIME t;
    GetSystemTime(&t);
    sprintf(timestamp, "%02d%02d%02d%03d", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    return timestamp;
#else
    struct timeval te;
    gettimeofday(&te, NULL);
    long long milliseconds = te.tv_sec * 1000LL + te.tv_usec / 1000;
    char* c_time_string = calloc(200, sizeof(char));
    sprintf(c_time_string, "%lld", milliseconds);
    return c_time_string;
#endif
}


char* enc_passw(char* passw) {

    char* enc_passw = calloc(512, sizeof(char));
    sprintf(enc_passw, "#PWD_INSTAGRAM_BROWSER:0:%s:%s", timestamp_in_char(), passw);
    return enc_passw;

}

char* _sign(int sign) {
    char* sign_chr = calloc(100, sizeof(char));
    if (sign == ER) {
        sprintf(sign_chr, "[%s-%s] ", RED, reset);
        return sign_chr;
    }
    else if (sign == WR) {
        sprintf(sign_chr, "[%s!%s] ", YEL, reset);
        return sign_chr;
    }
    else if (sign == IN) {
        sprintf(sign_chr, "[%s*%s] ", MAG, reset);
        return sign_chr;
    }
    else if (sign == GD) {
        sprintf(sign_chr, "[%s+%s] ", GRN, reset);
        return sign_chr;
    }

}

void clear() {

#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif

}


char* recv_res(SSL** ssl_sock) {
    int free_space = 0, all_bytes = 0, recv_size = 0, alloc_memmory = 0;
    char  _res[_1KB] = "";
    ZeroChar(_res);
    alloc_memmory = _1KB * sizeof(char*);
    char* res = calloc(alloc_memmory, sizeof(char*)), * ptr = NULL;
    while ((recv_size = SSL_read(*ssl_sock, _res, _1KB)) != 0) {
        all_bytes += recv_size;
        free_space = alloc_memmory - all_bytes;
        if (all_bytes >= alloc_memmory) {
            alloc_memmory += alloc_memmory + all_bytes * sizeof(char*);
            ptr = realloc(res, all_bytes);
#ifndef _WIN32        
            if (ptr != NULL) {
                free(ptr);
                ptr = NULL;
            }
#endif 
        }
        else if (recv_size >= free_space) {
            alloc_memmory += alloc_memmory * sizeof(char*);
            ptr = realloc(res, all_bytes);
#ifndef _WIN32
            if (ptr != NULL) {
                free(ptr);
                ptr = NULL;
            }
#endif 
        }
        strcat(res, _res);
#ifdef _WIN32
        ZeroMemory(_res, recv_size);
#else
        ZeroChar(_res);
#endif
    }
    return res;
}

char* remove_word(char* str, char* word_to_remove) {
    int strl = strlen(str);
    int wrdl = strlen(word_to_remove);
    char* new_word = calloc(strl - wrdl + 1, sizeof(char*));
    int i = 0, j = 0;

_start:;

    for (j; j < wrdl;) {
        char wrd_chr = word_to_remove[j];
        char str_chr = str[i];
        if (str_chr == wrd_chr) {
            str++;
            j++;
            goto _start;
        }
        else {
            j = 0;
            goto _start;
        }
    }
    strcat(new_word, str);
    return new_word;
}


char* create_uuid() {
#ifdef WIN32
    UUID uuid;
    UuidCreate(&uuid);
    RPC_CSTR* str;
    UuidToStringA(&uuid, &str);
    return str;
#else
    uuid_t uuid;
    uuid_generate_random(uuid);
    char* s = calloc(37, sizeof(char));
    uuid_unparse(uuid, s);
    return s;
#endif
}



char* get_cookie_value_by_key(char* res, char* key) {
    char** split_res = split(res, "\r\n");
    for (int i = 0;; i++) {
        char* element = split_res[i];
        if (strstr(split_res[i], "Set-Cookie") != NULL) {
            char* key_val = remove_word(element, "Set-Cookie: ");
            if (strstr(key_val, key) != NULL) {
                char* value = split(key_val, "=")[1];
                value = split(value, ";")[0];
                return value;
            }
        }
    }
}

char* hostname_to_ip(const char* hostname) {
    struct hostent* he;
    struct in_addr** addr_list;
    int i;
    char* ip = malloc(100);
    if ((he = gethostbyname(hostname)) == NULL)
    {
        perror("gethostbyname");
        return NULL;
    }

    addr_list = (struct in_addr**)he->h_addr_list;

    for (i = 0; addr_list[i] != NULL; i++)
    {
        strcpy(ip, inet_ntoa(*addr_list[i]));
        return ip;
    }
    return NULL;
}

void free_array(void* __f, size_t size_alloc) {
    memset(__f, 0, size_alloc);
}

char* payload_encode(const char* _data) {
    CURL* curl = curl_easy_init();
    char* output = curl_easy_escape(curl, _data, strlen(_data));
    char* encode = strrpc(output, "%20", "+");
    encode = strrpc(encode, "%3D", "=");
    encode = strrpc(encode, "%26", "&");
    return encode;
}

SSL* ssl_connect(sock_data* sk_dt) {

    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(sk_dt->IP);
    server.sin_family = AF_INET;
    server.sin_port = htons(sslPORT);

    if ((sk_dt->s = createsocket()) == INVALID_SOCKET) {
        printf("%sError While Create Socket !\n", _sign(ER));
#ifdef _WIN32
        system("pause");
#endif
        return NULL;
    }

    if (connect(sk_dt->s, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
        printf("%sError while connect to instagram server !\n", _sign(ER));
#ifdef _WIN32
        system("pause");
#endif
        return NULL;
    }

    initSSL();
    sk_dt->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    sk_dt->ssl_sock = SSL_new(sk_dt->ssl_ctx);
    SSL_set_fd(sk_dt->ssl_sock, sk_dt->s);
    int err = SSL_connect(sk_dt->ssl_sock);
    if (err != 1) {
        printf("%sError while send payload to instagram !\n", _sign(ER));
#ifdef _WIN32
        system("pause");
#endif
        return  NULL;
    }
    return sk_dt->ssl_sock;
}
void free_sock_data(sock_data* sk_dt) {
    ZeroMemory(sk_dt->ssl_sock, sizeof(sk_dt->ssl_sock));
    ZeroMemory(&sk_dt->s, sizeof(sk_dt->s));
}

void free_char(char* str) {
    int len = strlen(str);
    if (len != 0) {
        for (int i = 0; i <= len; i++) {
            str[i] = '\0';
        }
    }
}

const char* get_json_obj_key_array(JObject jobj, char* array[]) {
    JObject j = jobj;
    const char* val;
    int _array_size = array_size(array);
    for (int i = 0; i < _array_size; i++) {
        char* element = array[i];
        j = JOget(j, element);
    }
    val = JSget(j);
    return val;
}

const char* getid(char* username, COOKIES* cok, char* headers, SSL** ssl_sock) {

    char METHOD[4096];
    sprintf(METHOD, "GET /api/v1/feed/user/%s/username/ HTTP/1.1\r\n", username);
    char  mid[124];
    sprintf(mid, "x-mid: %s\r\n", cok->mid);
    strcat(METHOD, headers);
    strcat(METHOD, cok->cookie_header);
    strcat(METHOD, mid);
    strcat(METHOD, "\r\n");
    if (SSL_write(*ssl_sock, METHOD, strlen(METHOD)) < 0) {
        printf("%sError while send payload to instagram !\n", _sign(ER));
#ifdef _WIN32
        system("pause");
#endif
        return NULL;
    }

    char* res = recv_res(*&ssl_sock);
    char* content = strstr(res, "\r\n\r\n");
    if (content != NULL) {
        content += 4;
    }
    else {
        content = res;
    }
    JObject itObj = json_tokener_parse(content);
    const char* pk = get_json_obj_key_array(itObj, (char* []) { "user", "pk" });
    return pk;
}

char* get_status_code(char* res) {
    char* split_res = strtok(res, "\r\n");
    return split_res;
}
