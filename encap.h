#ifndef ENCAP_H__
#define ENCAP_H__

#include <linux/socket.h>

#include "dev.h"

extern struct sock *upf_encap_enable(int, int, struct upf_dev *);
extern void upf_encap_disable(struct sock *);

#endif
