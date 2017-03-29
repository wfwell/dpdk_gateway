#if 0
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/highmem.h>
#include <linux/kmod.h>
#include <linux/kallsyms.h>
#include <linux/delay.h>
#include <asm/system.h>
#include <linux/ipv6.h>
#endif

#include "cap_trans.h"
#include "cap_ipv6_ss.h"
#include "cap_ipv6_hashrbtree.h"
#include "cap_ipv6_multintrie.h"
#include <pthread.h>
#include <time.h>
//#include <netinet/ip6.h>



//MODULE_DESCRIPTION("IPv6 Address Store & Search Module");
//MODULE_AUTHOR("Husong ,husong@husong.com 2009-04-01");
//MODULE_LICENSE("GPL");
//MODULE_VERSION("4.0");


static unsigned long   MemoryPoolSize1=1024*1024*1;

static unsigned long   MemoryPoolSize2=1024*1024*32;

static struct rb_root*g_table=NULL;
static pthread_mutex_t g_ipv6status_lock;



unsigned long get_ipv6_status(unsigned char*ip)
{
	//unsigned long flags;
	unsigned long status=0;
	struct my_rbnode*mynode=NULL;

	//read_lock_irqsave(&g_ipv6status_lock,flags);
        pthread_mutex_lock(&g_ipv6status_lock);
	mynode=hash_rbtree_search(g_table,ip);
	status=mynode?mynode->attr.status:multi_ntrie_get_status(ip);
	//read_unlock_irqrestore(&g_ipv6status_lock,flags);
        pthread_mutex_unlock(&g_ipv6status_lock);
	return status;
}

void get_ipv6_all(struct trans_ioctl_ipv6 *attr)
{//get ipv6 address's flow and status
	//unsigned long flags;
	struct my_rbnode* mynode=NULL;
//		
	//read_lock_irqsave(&g_ipv6status_lock,flags);
        pthread_mutex_lock(&g_ipv6status_lock);
	mynode=hash_rbtree_search(g_table,attr->net);
	if(mynode){
		memcpy(attr, &(mynode->attr), sizeof(struct trans_ioctl_ipv6));
	}else{
		attr->status = multi_ntrie_get_status(attr->net);
		attr->lasttime_in=0;
		attr->lasttime_out=0;
		attr->bytes_in=0;
		attr->bytes_out=0;
		attr->bytesN_in=0;
		attr->bytesN_out=0;
		attr->pkts_in=0;
		attr->pkts_out=0;
	}
	//read_unlock_irqrestore(&g_ipv6status_lock,flags);
         pthread_mutex_unlock(&g_ipv6status_lock);
}




int set_ipv6_status(unsigned char * netprefix,unsigned long prefixlen,unsigned long status)
{
	//unsigned long flags;

	int ret=0;
//	
	//write_lock_irqsave(&g_ipv6status_lock,flags);
         pthread_mutex_lock(&g_ipv6status_lock);
//	
	if(prefixlen==128){
		if(multi_ntrie_get_status(netprefix)==status){//same status exists in m-tries,
			hash_rbtree_delete(g_table,netprefix);
		}else{
			ret=hash_rbtree_insert(g_table,netprefix,status,1 /*int overwrite*/);
		}
	}
	else{
		ret=multi_ntrie_set_status(netprefix,prefixlen,status);
	}
//
	//write_unlock_irqrestore(&g_ipv6status_lock,flags);
         pthread_mutex_unlock(&g_ipv6status_lock);
//
	return ret;
}


static  struct trans_ioctl_ipv6 * __get_ipv6_status_and_flow_ptr(unsigned char*ip,unsigned long *status)
{
	struct my_rbnode* mynode=hash_rbtree_search(g_table,ip);
	if(mynode){
		*status=mynode->attr.status;
		return &(mynode->attr);
	}else{
		*status=multi_ntrie_get_status(ip);
		return NULL;
	}
}

unsigned long transfer_test_and_merge_flow6(struct ip6_hdr *ipv6h)//struct ipv6hdr*ipv6h
{
	//unsigned long flags;

	struct trans_ioctl_ipv6 *sipnode=NULL;
	struct trans_ioctl_ipv6 *dipnode=NULL;
	unsigned long scntl;
	unsigned long dcntl;
	unsigned long ok_to_go;
	unsigned short payload_len;

	//write_lock_irqsave(&g_ipv6status_lock,flags);
        pthread_mutex_lock(&g_ipv6status_lock);
	sipnode = __get_ipv6_status_and_flow_ptr((unsigned char*)&(ipv6h->ip6_src),&scntl);
	dipnode = __get_ipv6_status_and_flow_ptr((unsigned char*)&(ipv6h->ip6_dst),&dcntl);
	ok_to_go=transfer_test_with_status(scntl, dcntl);
	payload_len=ntohs(ipv6h->ip6_plen);
	
	if(ok_to_go){
		
		if(sipnode){
			sipnode->pkts_out ++;
			sipnode->lasttime_out = time(NULL);

			if(dcntl == IPVO_FREE)
				sipnode->bytesN_out += payload_len;
			else
				sipnode->bytes_out += payload_len;			
		}

		if(dipnode){
			dipnode->pkts_in ++;
			dipnode->lasttime_in = time(NULL);

			if(scntl == IPVO_FREE)
				dipnode->bytesN_in += payload_len;
			else
				dipnode->bytes_in += payload_len;		
		}
		
	}
	//write_unlock_irqrestore(&g_ipv6status_lock,flags);
         pthread_mutex_unlock(&g_ipv6status_lock);
	return ok_to_go;
}



int print_ipv6_memory_info(void)
{
	//unsigned long flags;

	//write_lock_irqsave(&g_ipv6status_lock,flags);
         pthread_mutex_lock(&g_ipv6status_lock);
	multi_ntrie_print_memory();
	hash_rbtree_print_memory();
         pthread_mutex_unlock(&g_ipv6status_lock);
	//write_unlock_irqrestore(&g_ipv6status_lock,flags);
	return 0;
}



//EXPORT_SYMBOL(get_ipv6_status);
//EXPORT_SYMBOL(get_ipv6_all);
//EXPORT_SYMBOL(set_ipv6_status);
//EXPORT_SYMBOL(transfer_test_and_merge_flow6);
//EXPORT_SYMBOL(print_ipv6_memory_info);


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int  cap_ipv6_ss_init(void)
{
	int result;

	//rwlock_init(&g_ipv6status_lock);
        pthread_mutex_init(&g_ipv6status_lock,NULL);
	result=multi_ntrie_init(MemoryPoolSize1,MemoryPoolSize2);
	if(result)
		goto error1;

	result=hash_rbtree_init(&g_table);
	if(result)
		goto error2;

	return 0;


error2:
	hash_rbtree_free(&g_table);

error1:
	multi_ntrie_free();


	return result;
}

void  cap_ipv6_ss_exit(void)
{
	hash_rbtree_free(&g_table);
	multi_ntrie_free();
}

//module_init(cap_ipv6_ss_init);
//module_exit(cap_ipv6_ss_exit);

