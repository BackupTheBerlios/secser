#ifndef ADHOC_PARSER_H
#define ADHOC_PARSER_H

#define ADDR_START 0
#define QUOTE_START 1
#define QUOTE_END 2
#define ADDR_BEGIN 3
#define ADDR_END 4

#ifndef EXTERN_UNLESS_MAIN_MODULE
  #ifndef INCLUDED_BY_MAIN_MODULE
     #define EXTERN_UNLESS_MAIN_MODULE extern
  #else
     #define EXTERN_UNLESS_MAIN_MODULE
  #endif
#endif

EXTERN_UNLESS_MAIN_MODULE int parser_debug_mode;

#define LOG_PARSER parser_debug_mode

typedef struct hdr_str hdr;
struct hdr_str {
  char* begin;
  char* end;
  hdr* next;
};


#endif /* ADHOC_PARSER_H */
