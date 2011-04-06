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

#ifndef my_slow_tran_capture_h
#define my_slow_tran_capture_h

#define CAPTURE_LENGTH          65535
#define READ_TIMEOUT            2000
#define INBOUND 1
#define OUTBOUND 0
#define SUB_MSEC(x,y) \
( (x.tv_sec - y.tv_sec )*1000 \
+ (x.tv_usec - y.tv_usec)/1000 )

#define C_STRING_WITH_LEN(X) ((char *) (X)), ((size_t) (sizeof(X) - 1))

typedef struct queries_t{
  struct timeval tv;
  bool direction;
  char* query;
  struct queries_t *next;
  struct queries_t *end;
} queries_t;


extern char *optarg;
extern int optind, opterr, optopt;

struct st_mysql_lex_string
{
  char *str;
  size_t length;
};
typedef struct st_mysql_lex_string LEX_STRING;


#endif

