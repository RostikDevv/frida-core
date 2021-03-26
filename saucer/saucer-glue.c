#include "saucer-glue.h"

#ifdef HAVE_WINDOWS
# include <winsock2.h>
#else
# include <netinet/in.h>
# include <netinet/tcp.h>
#endif

void
frida_saucer_tcp_enable_nodelay (GSocket * socket)
{
  g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY, TRUE, NULL);
}
