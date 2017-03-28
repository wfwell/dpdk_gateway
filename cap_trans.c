#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/spinlock.h>

#include <asm/atomic.h>
#include <asm/cache.h>
#include <asm/byteorder.h>

#include <linux/types.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/checksum.h>
#include <linux/ioctl.h>

#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/if_bridge.h>
#include <net/dst.h>
#include <net/pkt_sched.h>
#include <net/checksum.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/netpoll.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <linux/wireless.h>
#include <net/iw_handler.h>
#include <asm/current.h>
#include <linux/audit.h>
#include <linux/dmaengine.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <linux/page-flags.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>


#include "cap_trans.h"
#include "cap_ipv4_ss.h"
#include "cap_ipv6_ss.h"
#include "cap_redirect.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CERNET.COM R&D DEPT.");
MODULE_DESCRIPTION("Transfer packets: receive packets from cap_pack and determine whether to transfer packets between two nic");
MODULE_VERSION("Version 2.0");


struct transfer_config_status {
	spinlock_t lock;
	unsigned long		trans_up;
	struct	net_device	*dev_inner;
	struct  net_device	*dev_outer;
};

static struct transfer_config_status 	real_info;
static struct transfer_config_status *  info=&real_info;






////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////



static int trans_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	unsigned long flags;
	int	err = 0;

	switch(cmd) {

		case CAP_TRANS_IOCTL_UP:
		{
			spin_lock_irqsave(&info->lock,flags);	
			info->trans_up = 1;
			spin_unlock_irqrestore(&info->lock,flags);	
			
			break;
		}
		case CAP_TRANS_IOCTL_DOWN:
		{
			spin_lock_irqsave(&info->lock,flags);	
			info->trans_up = 0;
			spin_unlock_irqrestore(&info->lock,flags);	
			
			break;
		}
		
		case CAP_TRANS_IOCTL_SET_DEVICE:
		{
			struct trans_ioctl_transfer input;
			struct	net_device	*dev_inner = NULL;
			struct	net_device	*dev_outer = NULL;
			struct	net_device  *dev =NULL;

			if(copy_from_user(&input,(void *)arg,sizeof(input))) {
				err = -EFAULT;
				goto out;
			}

			dev_inner=dev_get_by_name(&init_net ,input.inner);
			dev_outer=dev_get_by_name(&init_net ,input.outer);

			if( dev_inner == NULL || dev_outer == NULL){
				if(dev_inner)
					dev_put(dev_inner);
				else
					printk(KERN_ALERT"Net device %s not Found!\n",input.inner);
				
				if(dev_outer)
					dev_put(dev_outer);
				else
					printk(KERN_ALERT"Net device %s not Found!\n",input.outer);
				
				err = -ENODEV;
				goto out;
			}
			
			spin_lock_irqsave(&info->lock,flags);	


			if(info->dev_inner){
				dev=info->dev_inner;
				info->dev_inner=dev_inner;
				dev_put(dev);
			}else{
				info->dev_inner=dev_inner;
			}

			if(info->dev_outer){
				dev=info->dev_outer;
				info->dev_outer=dev_outer;
				dev_put(dev);
			}else{
				info->dev_outer=dev_outer;
			}

			info->dev_inner->features |=   NETIF_F_NO_CSUM;
			info->dev_inner->features &= ~NETIF_F_HW_CSUM;
			info->dev_inner->features &= ~NETIF_F_IP_CSUM;
			
			info->dev_outer->features |=   NETIF_F_NO_CSUM;
			info->dev_outer->features &= ~NETIF_F_HW_CSUM;
			info->dev_outer->features &= ~NETIF_F_IP_CSUM;
			
			spin_unlock_irqrestore(&info->lock,flags);	


			break;
		}

		case CAP_TRANS_IOCTL_GET_DEVICE:
		{
			struct trans_ioctl_transfer input;
			if(copy_from_user(&input,(void *)arg,sizeof(input))) {
				err = -EFAULT;
				goto out;
			}


			spin_lock_irqsave(&info->lock,flags);	


			input.trans_up=info->trans_up;

			if(info->dev_inner){
				strcpy(input.inner, info->dev_inner->name);
			}else {
				strcpy(input.inner, "");
			}

			if(info->dev_outer){
				strcpy(input.outer, info->dev_outer->name);
			}else {
				strcpy(input.outer, "");
			}


			spin_unlock_irqrestore(&info->lock,flags);	


			if(copy_to_user((void *)arg,&input,sizeof(input))) {
				err = -EFAULT;
				goto out;
			} 

			break;
		}




		case CAP_TRANS_IOCTL_IPV6_SET:
		{
			struct trans_ioctl_ipv6 input;
			if(copy_from_user(&input,(void *)arg,sizeof(input))) {
				err = -EFAULT;
				goto out;
			}

			err=set_ipv6_status(input.net ,input.prefixlength,input.status);

			break;
		}

		case CAP_TRANS_IOCTL_IPV6_GET:
		{
			struct trans_ioctl_ipv6 input;
			if(copy_from_user(&input,(void *)arg,sizeof(input))) {
				err = -EFAULT;
				goto out;
			}
			
			input.status=get_ipv6_status(input.net);

			if(copy_to_user((void *)arg,&input,sizeof(input))) {
				err = -EFAULT;
				goto out;
			} 

			break;
		}
		
		case CAP_TRANS_IOCTL_IPV6_GET_ALL:
		{
			struct trans_ioctl_ipv6 input;
			if(copy_from_user(&input,(void *)arg,sizeof(input))) {
				err = -EFAULT;
				goto out;
			}
			
			get_ipv6_all(&input);
			
			if(copy_to_user((void *)arg,&input,sizeof(input))) {
				err = -EFAULT;
				goto out;
			} 

			break;
		}		

		case CAP_TRANS_IOCTL_IPV6_PRINT://just for test!!!
		{
			
			print_ipv6_memory_info();
			
			break;
		}


		case CAP_TRANS_IOCTL_IPV4_SET:
		{
			struct trans_ioctl_ipv4 input;
			if(copy_from_user(&input,(void *)arg,sizeof(input))) {
				err = -EFAULT;
				goto out;
			}

			err=set_ipv4_status(input.net ,input.prefixlength,input.status);

			break;
		}

		case CAP_TRANS_IOCTL_IPV4_GET:
		{
			struct trans_ioctl_ipv4 input;
			if(copy_from_user(&input,(void *)arg,sizeof(input))) {
				err = -EFAULT;
				goto out;
			}
			
			input.status=get_ipv4_status(input.net);

			if(copy_to_user((void *)arg,&input,sizeof(input))) {
				err = -EFAULT;
				goto out;
			} 

			break;
		}
		
		case CAP_TRANS_IOCTL_IPV4_GET_ALL:
		{
			struct trans_ioctl_ipv4 input;
			if(copy_from_user(&input,(void *)arg,sizeof(input))) {
				err = -EFAULT;
				goto out;
			}
			
			get_ipv4_all(&input);
			
			if(copy_to_user((void *)arg,&input,sizeof(input))) {
				err = -EFAULT;
				goto out;
			} 

			break;
		}		

		case CAP_TRANS_IOCTL_IPV4_PRINT://just for test!!!
		{
		
			print_ipv4_memory_info();
			
			break;
		}
			
			

		case CAP_TRANS_IOCTL_SET_REDIRECT:
		{
			struct trans_ioctl_redirect input;
			if(copy_from_user(&input,(void *)arg,sizeof(input))) {
				err = -EFAULT;
				goto out;
			}
			
			set_redirect_timeout(input.timeout);
			set_redirect_url(input.url);
			
			break;
		}
		
		case CAP_TRANS_IOCTL_GET_REDIRECT:
		{
			struct trans_ioctl_redirect output;
			output.timeout=get_redirect_timeout();
			get_redirect_url(output.url);	
			
			if(copy_to_user((void *)arg,&output,sizeof(output))) {
				err = -EFAULT;
				goto out;
			} 
			
			break;
		}
		
		default:
		{
			err = -ENOIOCTLCMD;
			break;
		}
	}	
out:	
	return err;
}	


static int trans_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	sock_orphan(sk);
	sock_put(sk);
	
	return 0;
}

static int trans_hook(struct sk_buff *skb)
{
	struct    net_device *to_dev;
	__be16	type;

	if(info->trans_up==0)
		return NET_RX_SUCCESS;

	if( (!skb) || (!skb->dev)  )
			return NET_RX_SUCCESS;


	if(skb->dev==info->dev_inner)
		to_dev =info->dev_outer;
	else if(skb->dev==info->dev_outer)
		to_dev =info->dev_inner;
	else
		return NET_RX_SUCCESS;


	if( netif_queue_stopped(to_dev) || !info->trans_up )
		goto drop;


	type = skb->protocol;

	if(type== htons(ETH_P_IPV6))
	{	
		if (transfer_test_and_merge_flow6(skb->network_header))
			goto xmit;
		
		if(get_ipv6_status(&ipv6_hdr(skb)->saddr)==IPVI_UNAUTH)
		{//ipv6 redirect begin
			redirected_skb_enqueue(skb);
			return NET_RX_DROP;//
		}//ipv6 redirect end

		goto drop;
	
	}else if(type== htons(ETH_P_IP)){
#ifndef NO_IPV4
		if (transfer_test_and_merge_flow4(skb->network_header))
#endif
			goto xmit;

		if(get_ipv4_status(&ip_hdr(skb)->saddr)==IPVI_UNAUTH)
		{//ipv4 redirect begin
			redirected_skb_enqueue(skb);
			return NET_RX_DROP;//
		}//ipv4 redirect end

		goto drop;

	}else if(type== htons(0x88cc))//LLDP
	{
		return NET_RX_SUCCESS;
	}else
	{
		goto xmit;
	}

drop:
	kfree_skb(skb);
	return NET_RX_DROP;

xmit:

	skb->dev=to_dev;
	skb->ip_summed=CHECKSUM_COMPLETE;
	skb_push(skb, sizeof(struct ethhdr));

	dev_queue_xmit(skb);

	return NET_RX_DROP;
}


struct proto_ops gateway_proto_ops = {
	family:         PF_TRANS,
	release:        trans_release,
	ioctl:          trans_ioctl,
	bind:           sock_no_bind,
	connect:        sock_no_connect,
	socketpair:     sock_no_socketpair,
	accept:         sock_no_accept,
	getname:        sock_no_getname,
	poll:           sock_no_poll,
	listen:         sock_no_listen,
	shutdown:       sock_no_shutdown,
	setsockopt:     sock_no_setsockopt,
	getsockopt:     sock_no_getsockopt,
	sendmsg:        sock_no_sendmsg,
	recvmsg:        sock_no_recvmsg,
	mmap:           sock_no_mmap
};


static struct proto gateway_proto = {
	.name	  = "gateway",
	.owner	  = THIS_MODULE,
	.obj_size	  = sizeof(struct sock),
};


static int trans_create(struct net *net,struct socket *sock, int protocol)
{
	struct sock *sk;

	int err;

	sock->state = SS_UNCONNECTED;

	if(!capable(CAP_NET_RAW))
		return -EPERM;
	
	sock->ops = &gateway_proto_ops;

	err = -ENOBUFS;
	sk = sk_alloc(net,PF_TRANS, GFP_ATOMIC, &gateway_proto);
	if (sk == NULL)
		return -ENOBUFS;

	sock_init_data(sock, sk);

	sk->sk_reuse = 1;
	sk->sk_family	   = PF_TRANS;
	sk->sk_protocol	   = protocol;

	return 0;
}	



static struct net_proto_family trans_family_ops = {
	.family=PF_TRANS,
	.create=trans_create,
	.owner=THIS_MODULE,
};


void           set_transfer_hook(unsigned long);

int __init init_af_trans(void)
{
	int i;

	memset(info,0,sizeof(*info));	
	spin_lock_init(&info->lock);
	info->trans_up = 0;
	
	sock_register(&trans_family_ops);
	set_transfer_hook(trans_hook);
	

	return 0;
}

void  __exit exit_af_trans(void)
{

	unsigned long flags;
	
	set_transfer_hook(NULL);
	sock_unregister(PF_TRANS);
	
//	
	spin_lock_irqsave(&info->lock,flags);
//	

	info->trans_up = 0;

	if(info->dev_inner)
		dev_put(info->dev_inner);
	if(info->dev_outer)
		dev_put(info->dev_outer);
	
//
	spin_unlock_irqrestore(&info->lock,flags);
//

	return;
}

module_init(init_af_trans);
module_exit(exit_af_trans);
