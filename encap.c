#include <linux/socket.h>
#include <linux/rculist.h>
#include <linux/udp.h>

#include <net/ip.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>

#include "dev.h"
#include "encap.h"

static void upf_encap_disable_locked(struct sock *);
static int upf_encap_recv(struct sock *, struct sk_buff *);

struct sock *upf_encap_enable(int fd, int type, struct upf_dev *upf)
{
	struct udp_tunnel_sock_cfg tuncfg = {};
	struct socket *sock;
	struct sock *sk;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return NULL;

	if (sock->sk->sk_protocol != IPPROTO_UDP) {
		sockfd_put(sock);
		return ERR_PTR(-EINVAL);
	}

	lock_sock(sock->sk);
	if (sock->sk->sk_user_data) {
		release_sock(sock->sk);
		sockfd_put(sock);
		return ERR_PTR(-EBUSY);
	}

	sk = sock->sk;
	sock_hold(sk);

	tuncfg.sk_user_data = upf;
	tuncfg.encap_type = type;
	tuncfg.encap_rcv = upf_encap_recv;
	tuncfg.encap_destroy = upf_encap_disable_locked;

	setup_udp_tunnel_sock(sock_net(sock->sk), sock, &tuncfg);

	release_sock(sock->sk);
	sockfd_put(sock);
	return sk;
}

void upf_encap_disable(struct sock *sk)
{
	struct upf_dev *upf;

	if (!sk)
		return;

	lock_sock(sk);
	upf = sk->sk_user_data;
	if (upf) {
		upf->sk1u = NULL;
		udp_sk(sk)->encap_type = 0;
		rcu_assign_sk_user_data(sk, NULL);
		sock_put(sk);
	}
	release_sock(sk);
}

static void upf_encap_disable_locked(struct sock *sk)
{
	rtnl_lock();
	upf_encap_disable(sk);
	rtnl_unlock();
}

static int upf_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct upf_dev *upf;

	upf = rcu_dereference_sk_user_data(sk);
	if (!upf)
		return 1;

	if (udp_sk(sk)->encap_type != UDP_ENCAP_GTP1U) {
		kfree_skb(skb);
		return 0;
	}

	// upf_udp_encap_recv(upf, skb);
	kfree_skb(skb);
	return 0;
}
