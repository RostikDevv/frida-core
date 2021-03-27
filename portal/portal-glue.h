#ifndef __FRIDA_PORTAL_GLUE_H__
#define __FRIDA_PORTAL_GLUE_H__

#include <gio/gio.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL void frida_portal_tcp_enable_nodelay (GSocket * socket);

G_END_DECLS

#endif
