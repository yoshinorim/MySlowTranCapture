/**
 *   MySlowTranCapture -- Capturing Slow MySQL Transactions
 *   Copyright (C) 2011 DeNA Co.,Ltd. 
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h>

#include <boost/regex.hpp>
#include <tr1/unordered_map>

#include "my_slow_tran_capture.h"

#include "sll.h"
#include "local_addresses.h"


std::tr1::unordered_map<uint64_t, queries_t*> trans;
uint alert_millis= 4000;
uint max_packets= 0;
bool old_protocol= 0;

const char *begin_pattern= "\\s*BEGIN\\s*";
const char *commit_pattern= "\\s*COMMIT\\s*";
const char *rollback_pattern= "\\s*ROLLBACK\\s*";
const char *autocommit0_pattern= "\\s*SET\\s+AUTOCOMMIT\\s*=\\s*0\\s*";
const char *autocommit1_pattern= "\\s*SET\\s+AUTOCOMMIT\\s*=\\s*1\\s*";

boost::regex begin_exp(begin_pattern,
  boost::regbase::normal | boost::regbase::icase);
boost::regex commit_exp(commit_pattern,
  boost::regbase::normal | boost::regbase::icase);
boost::regex rollback_exp(rollback_pattern,
  boost::regbase::normal | boost::regbase::icase);
boost::regex autocommit0_exp(autocommit0_pattern,
  boost::regbase::normal | boost::regbase::icase);
boost::regex autocommit1_exp(autocommit1_pattern,
  boost::regbase::normal | boost::regbase::icase);

enum enum_server_command
{
  COM_SLEEP, COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST,
  COM_CREATE_DB, COM_DROP_DB, COM_REFRESH, COM_SHUTDOWN, COM_STATISTICS,
  COM_PROCESS_INFO, COM_CONNECT, COM_PROCESS_KILL, COM_DEBUG, COM_PING,
  COM_TIME, COM_DELAYED_INSERT, COM_CHANGE_USER, COM_BINLOG_DUMP,
  COM_TABLE_DUMP, COM_CONNECT_OUT, COM_REGISTER_SLAVE,
  COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_SEND_LONG_DATA, COM_STMT_CLOSE,
  COM_STMT_RESET, COM_SET_OPTION, COM_STMT_FETCH, COM_DAEMON,
  /* don't forget to update const char *command_name[] in sql_parse.cc */

  /* Must be last */
  COM_END
};

const LEX_STRING command_name[]={
  { C_STRING_WITH_LEN("Sleep") },
  { C_STRING_WITH_LEN("Quit") },
  { C_STRING_WITH_LEN("Init DB") },
  { C_STRING_WITH_LEN("Query") },
  { C_STRING_WITH_LEN("Field List") },
  { C_STRING_WITH_LEN("Create DB") },
  { C_STRING_WITH_LEN("Drop DB") },
  { C_STRING_WITH_LEN("Refresh") },
  { C_STRING_WITH_LEN("Shutdown") },
  { C_STRING_WITH_LEN("Statistics") },
  { C_STRING_WITH_LEN("Processlist") },
  { C_STRING_WITH_LEN("Connect") },
  { C_STRING_WITH_LEN("Kill") },
  { C_STRING_WITH_LEN("Debug") },
  { C_STRING_WITH_LEN("Ping") },
  { C_STRING_WITH_LEN("Time") },
  { C_STRING_WITH_LEN("Delayed insert") },
  { C_STRING_WITH_LEN("Change user") },
  { C_STRING_WITH_LEN("Binlog Dump") },
  { C_STRING_WITH_LEN("Table Dump") },
  { C_STRING_WITH_LEN("Connect Out") },
  { C_STRING_WITH_LEN("Register Slave") },
  { C_STRING_WITH_LEN("Prepare") },
  { C_STRING_WITH_LEN("Execute") },
  { C_STRING_WITH_LEN("Long Data") },
  { C_STRING_WITH_LEN("Close stmt") },
  { C_STRING_WITH_LEN("Reset stmt") },
  { C_STRING_WITH_LEN("Set option") },
  { C_STRING_WITH_LEN("Fetch") },
  { C_STRING_WITH_LEN("Daemon") },
  { C_STRING_WITH_LEN("Error") }  // Last command number
};


void print_time(struct timeval tv)
{
  time_t timer;
  struct tm t;
  timer= tv.tv_sec;
  localtime_r(&timer, &t);
  printf("%d/%02d/%02d %02d:%02d:%02d.%ld",
         t.tm_year+1900, t.tm_mon+1,
         t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec);
}


void print_direction(bool direction)
{
  if(direction == INBOUND)
  {
    printf("->");
  }else
  {
    printf("<-");
  }
}


/* Make unique <raddr, rport> big integer id */
uint64_t make_key(struct in_addr raddr, uint16_t rport)
{
  /* in_addr.s_addr => uint32 */
  uint64_t key_addr= (uint64_t)raddr.s_addr;
  key_addr= key_addr << 16;
  return key_addr + rport;
}

void init_queue(queries_t* queue)
{
  queue->end= queue;
  queue->next= NULL;
}

void enqueue(queries_t* queue, queries_t* query)
{
  queue->end->next= query;
  queue->end= query;
}


int delete_queue(queries_t* queue)
{
  queries_t *tmp;
  while (queue != NULL)
  {
    tmp= queue;
    queue= queue->next;
    free(tmp->query);
    free(tmp);
  }
  return 0;
}


void clear_trans()
{
  std::tr1::unordered_map<uint64_t, queries_t* >::iterator it= trans.begin();
  while (it != trans.end())
  {
    queries_t* queue= it->second;
    delete_queue(queue);
    it++;
  }
  trans.clear();
}


void print_and_delete_queries(uint64_t key, queries_t* queries,
                  struct in_addr raddr, uint16_t rport, struct timeval tv)
{
  uint num_queries=0;
  bool do_print=0;
  queries_t *orig= queries;
  while (queries != NULL)
  {
    num_queries++;
    if (num_queries==1)
    {
      timeval begin_time= queries->tv;
      uint timediff= SUB_MSEC(tv, begin_time);
      if (timediff > alert_millis)
      {
        do_print= 1;
        char src[16], *addr;
        addr= inet_ntoa(raddr);
        strncpy(src, addr, 15);
        src[15]= '\0';
        printf("\nFrom %s:%d\n", src, rport);
      }else
        break;
    }
    if (do_print)
    {
      print_time(queries->tv);
      printf(" ");
      print_direction(queries->direction);
      printf("\n%s \n", queries->query);
      fflush(stdout);
    }
    queries= queries->next;
  }
  delete_queue(orig);
  trans.erase(key);
}


int outbound(struct tcphdr *tcp, struct timeval tv,
             struct in_addr raddr, uint16_t rport,
             const unsigned char *packet, const int datalen)
{
  uint64_t key= make_key(raddr, rport);

  unsigned char* p= (unsigned char*)packet;
  uint64_t plen= p[0] + (p[1]<<8)  + (p[2]<<16);
  p+= 4;
  int server_code= p[0];

  std::tr1::unordered_map<uint64_t, queries_t* >::iterator it;
  it= trans.find(key);
  if(it != trans.end())
  {
    char *str;
    if (server_code == 0) //OK
    {
      char *msg= "GOT_OK";
      int str_len= strlen(msg);
      str= (char*)malloc(str_len+1);
      sprintf(str, msg);
      str[str_len]= '\0';
    }else if (server_code == 255) //ERROR
    {
      char *msg_head= "GOT_ERR:";
      int head_len= strlen(msg_head);
      int protocol_head_len;
      if(old_protocol)
        protocol_head_len= 3;
      else
        protocol_head_len= 9;
      uint64_t errstr_len= plen - protocol_head_len;
      str= (char*)malloc(head_len+errstr_len+1);
      sprintf(str, msg_head);
      memcpy(str+head_len, p+protocol_head_len, errstr_len);
      str[head_len+errstr_len]= '\0';
    }else
    {
      char *msg= "GOT_RES";
      int str_len= strlen(msg);
      str= (char*)malloc(str_len+1);
      sprintf(str, msg);
      str[str_len]= '\0';
    }
    queries_t *t= (queries_t*)malloc(sizeof(queries_t));
    t->tv= tv;
    t->query= str;
    t->direction= OUTBOUND;
    t->next= NULL;
    queries_t* queries= it->second;
    enqueue(queries, t);
    trans[key]= queries;
  }
  return 0;
}


bool is_begin_tran(char* query, uint query_length)
{
  /* For performance reasons, avoiding using regular expression every time */
  if ((toupper(query[0]) == 'B' || /* BEGIN*/
      (query_length >= 3 && toupper(query[2]) == 'T')) && /* SET*/
      (boost::regex_match(query, begin_exp) ||
      boost::regex_match(query, autocommit0_exp)))
    return 1;
  return 0;
}

bool is_end_tran(char* query, uint query_length)
{
  if ((toupper(query[0]) == 'C' || toupper(query[0]) == 'R' ||
      (query_length >= 3 && toupper(query[2]) == 'T')) &&
      (boost::regex_match(query, commit_exp) ||
      boost::regex_match(query, rollback_exp) ||
      boost::regex_match(query, autocommit1_exp)))
    return 1;
  return 0;
}


void parse_query(uint64_t key, unsigned char *p, uint query_length,
                 struct timeval tv, struct in_addr raddr, uint16_t rport)
{
  queries_t *t= (queries_t*)malloc(sizeof(queries_t));
  char* query= (char*)malloc(query_length+1);
  memcpy(query, p, query_length);
  query[query_length]= '\0';
  t->tv= tv;
  t->query= query;
  t->direction= INBOUND;
  t->next= NULL;

  if (is_begin_tran(query, query_length))
  {
    std::tr1::unordered_map<uint64_t, queries_t* >::iterator it;
    it= trans.find(key);
    if (it != trans.end())
    {
      char *print_str= "TRAN_END BY ";
      int print_strlen= strlen(print_str);
      queries_t* queries= it->second;
      queries_t *t2= (queries_t*)malloc(sizeof(queries_t));
      char* query2= (char*)malloc(print_strlen+strlen(query)+1);
      sprintf(query2, "%s%s", print_str, query);
      t2->tv= tv;
      t2->query= query2;
      t2->direction= INBOUND;
      t2->next= NULL;
      enqueue(queries, t2);
      print_and_delete_queries(key, queries, raddr, rport, tv);
    }
    init_queue(t);
    trans[key]= t;
  }else if (is_end_tran(query, query_length))
  {
    std::tr1::unordered_map<uint64_t, queries_t* >::iterator it;
    it= trans.find(key);
    if (it != trans.end())
    {
      queries_t* queries= it->second;
      enqueue(queries, t);
      trans[key]= queries;
      print_and_delete_queries(key, queries, raddr, rport, tv);
    }else
    {
      free(t->query);
      free(t);
    }
  }else
  {
    std::tr1::unordered_map<uint64_t, queries_t* >::iterator it;
    it= trans.find(key);
    if (it != trans.end())
    {
      queries_t* queries= it->second;
      enqueue(queries, t);
      trans[key]= queries;
    }else
    {
      /* Guess that transactions start here. i.e. after SET AUTOCOMMIT=0*/
      init_queue(t);
      trans[key]= t;
    }
  }
}


void parse_quit(uint64_t key, struct timeval tv, struct in_addr raddr, 
                uint16_t rport)
{
  std::tr1::unordered_map<uint64_t, queries_t* >::iterator it;
  it= trans.find(key);
  if (it != trans.end())
  {
    char *quit_str= "QUIT";
    int quit_strlen= strlen(quit_str);
    queries_t *t= (queries_t*)malloc(sizeof(queries_t));
    char* query= (char*)malloc(quit_strlen+1);
    sprintf(query, quit_str);
    t->tv= tv;
    t->query= query;
    t->direction= INBOUND;
    t->next= NULL;
    queries_t* queries= it->second;
    enqueue(queries, t);
    trans[key]= queries;
    print_and_delete_queries(key, queries, raddr, rport, tv);
  }
}


void parse_command(uint64_t key, struct timeval tv, uint command)
{
  std::tr1::unordered_map<uint64_t, queries_t* >::iterator it;
  it= trans.find(key);
  if (it != trans.end())
  {
    char buf[64];
    queries_t *t= (queries_t*)malloc(sizeof(queries_t));
    sprintf(buf, "CMD %s", command_name[command].str);
    int length=strlen(buf);
    char* query= (char*)malloc(length + 1);
    memcpy(query, buf, length);
    query[length]= '\0';
    t->tv= tv;
    t->query= query;
    t->direction= INBOUND;
    t->next= NULL;
    queries_t* queries= it->second;
    enqueue(queries, t); 
    trans[key]= queries;
  }
}


int inbound(struct tcphdr *tcp, struct timeval tv, 
             struct in_addr raddr, uint16_t rport,
             const unsigned char *packet, const int datalen)
{
  uint64_t key= make_key(raddr, rport);
  unsigned char* p= (unsigned char*)packet;
  p+= 4;
  int command= p[0];
  switch (command)
  {
  case COM_QUERY:
    p++;
    parse_query(key, p, datalen-5, tv, raddr, rport);
    break;
  case COM_QUIT:
    parse_quit(key, tv, raddr, rport);
    break;
  default:
    if(command <= COM_END)
      parse_command(key, tv, command);
    break;
  } 
  return 0;
}


int process_ip(pcap_t *dev, const struct ip *ip, struct timeval tv,
               const unsigned char *packet, const int packetlen)
{
  bool incoming;
  unsigned len;

  if (is_local_address(ip->ip_src))
    incoming= 0;
  else if (is_local_address(ip->ip_dst))
    incoming= 1;
  else
    return 1;

  len= htons(ip->ip_len);
  switch (ip->ip_p)
  {
    struct tcphdr *tcp;
    uint16_t sport, dport;
    unsigned datalen;

  case IPPROTO_TCP:
    tcp= (struct tcphdr *) ((unsigned char *) ip + sizeof(iphdr));

    sport= ntohs(tcp->source);
    dport= ntohs(tcp->dest);
    datalen= len - sizeof(iphdr) - tcp->doff * 4;

    if (tcp->fin == 1)
    {
      if (incoming)
        parse_quit(make_key(ip->ip_src, sport), tv, ip->ip_src, sport);
      else
        parse_quit(make_key(ip->ip_dst, dport), tv, ip->ip_dst, dport);
      return 0;
    }

    if (datalen <= 4)
      return 0;
    if (incoming)
    {
      inbound(tcp, tv, ip->ip_src, sport,
              packet+(packetlen-datalen), datalen);
    }else
    {
      outbound(tcp, tv, ip->ip_dst, dport,
               packet+(packetlen-datalen), datalen);
    }
    break;

  default:
    break;
  }

  return 0;
}


int process_packet_header(const struct ip **ip, pcap_t *pcap,
                          const struct pcap_pkthdr *header,
                          const unsigned char *packet)
{
  const struct sll_header *sll;
  const struct ether_header *ether_header;
  unsigned short packet_type;

  switch (pcap_datalink(pcap))
  {
  case DLT_LINUX_SLL:
    sll= (struct sll_header *) packet;
    packet_type= ntohs(sll->sll_protocol);
    *ip= (const struct ip*) (packet + sizeof(struct sll_header));
    break;

  case DLT_EN10MB:
    ether_header= (struct ether_header *) packet;
    packet_type= ntohs(ether_header->ether_type);
    *ip= (const struct ip*) (packet + sizeof(struct ether_header));
    break;
  case DLT_RAW:
    packet_type= ETHERTYPE_IP;
    *ip= (const struct ip*) packet;
    break;

  default:
   return -1;
  }

  if (packet_type != ETHERTYPE_IP)
    return -2;

  return 0;
}


void process_packet(unsigned char *user, const struct pcap_pkthdr *header,
                    const unsigned char *packet)
{
  pcap_t *pcap= (pcap_t *) user;
  const struct ip *ip;

  if (!process_packet_header(&ip, pcap, header, packet))
    process_ip(pcap, ip, header->ts, packet, header->caplen);
}


void print_usage()
{
  printf("Usage: smtc -t <alert_millis> -i <interface> -f <filter_rule> "
         "-o (set if using older MySQL protocols)\n");
}


int main(int argc, char** argv)
{
  struct bpf_program bpf;
  char errbuf[PCAP_ERRBUF_SIZE];
  static char interface[128]= {0};
  static char filter[1024]= {0};
  pcap_t *pcap;
  int r;

  while ((r= getopt(argc, argv, "hi:t:f:m:o")) != -1)
  {
    switch (r)
    {
    case 'h':
      print_usage();
      return 0;
    case 'f':
      strncpy(filter, optarg, sizeof(filter)-1);
      filter[strlen(filter)]= '\0';
      break;
    case 'i':
      strncpy(interface, optarg, sizeof(interface)-1);
      interface[strlen(interface)]= '\0';
      break;
    case 't':
      alert_millis= atoi(optarg);
      break;
    case 'm':
      max_packets= atoi(optarg);
      break;
    case 'o':
      old_protocol= 1;
      break;
    default:
      break;
    }
  }

  /* Get local addresses */
  if (get_addresses() != 0)
    return -1;

  if (!interface || !strlen(interface))
    sprintf(interface, "any");

  printf("Monitoring %s interface..\n", interface);
  pcap= pcap_open_live(interface, CAPTURE_LENGTH, 0, READ_TIMEOUT, errbuf);
  if (!pcap)
  {
    fprintf(stderr, "pcap: %s\n", errbuf);
    return -2;
  }

  /* Capture only TCP port 3306*/
  if (strlen(filter) == 0)
  {
    sprintf(filter, "tcp port 3306");
    printf("Listening port 3306..\n");
  }else
  {
    printf("Filtering rule: %s\n", filter);
  }

  if (pcap_compile(pcap, &bpf, filter, 1, 0))
  {
    fprintf(stderr, "pcap: %s\n", pcap_geterr(pcap));
    return -3;
  }

  if (pcap_setfilter(pcap, &bpf)) {
    fprintf(stderr, "pcap: %s\n", pcap_geterr(pcap));
    return -4;
  }

  printf("Logging transactions that take more than %d milliseconds..\n", 
    alert_millis);

  if(old_protocol)
    printf("Capturing MySQL old protocols..\n");

  /* The -1 here stands for "infinity" */
  r= pcap_loop(pcap, (max_packets > 0) ? max_packets : -1, process_packet,
              (unsigned char *) pcap);
  if (r == -1) {
    fprintf(stderr, "pcap: %s\n", pcap_geterr(pcap));
    return -5;
  }

  /* close capture device */
  pcap_close(pcap);

  clear_trans();
  return 0;
}
