#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>


#define HEXDIG(x) (((x)>=10)?(x)-10+'A':(x)+'0')

/* fast ip_addr -> string convertor;
 * it uses an internal buffer
 */
char *
ip_addr2a (unsigned char *ip, int type)
{

  char buff[40] = { 0 };        /* 1234:5678:9012:3456:7890:1234:5678:9012\0 */
  int offset;
  register unsigned char a, b, c;
  char *tmp;
  int r;


  offset = 0;
  switch (type)
    {

    case AF_INET:
      for (r = 0; r < 3; r++)
        {
          a = ip[r] / 100;
          c = ip[r] % 10;
          b = ip[r] % 100 / 10;
          if (a)
            {
              buff[offset] = a + '0';
              buff[offset + 1] = b + '0';
              buff[offset + 2] = c + '0';
              buff[offset + 3] = '.';
              offset += 4;
            }
          else if (b)
            {
              buff[offset] = b + '0';
              buff[offset + 1] = c + '0';
              buff[offset + 2] = '.';
              offset += 3;
            }
          else
            {
              buff[offset] = c + '0';
              buff[offset + 1] = '.';
              offset += 2;
            }
        }
      /* last number */
      a = ip[r] / 100;
      c = ip[r] % 10;
      b = ip[r] % 100 / 10;
      if (a)
        {
          buff[offset] = a + '0';
          buff[offset + 1] = b + '0';
          buff[offset + 2] = c + '0';
          buff[offset + 3] = 0;
        }
      else if (b)
        {
          buff[offset] = b + '0';
          buff[offset + 1] = c + '0';
          buff[offset + 2] = 0;
        }
      else
        {
          buff[offset] = c + '0';
          buff[offset + 1] = 0;
        }
      break;

    default:
      printf ("error while converting\n");
      return 0;
    }
  tmp = (char *) strndup (buff, strlen (buff));
  return tmp;
}
