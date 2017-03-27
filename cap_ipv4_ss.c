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
#include <linux/ip.h>
#endif

#include "cap_trans.h"
#include "cap_ipv4_ss.h"
#include "cap_ipv4_hashrbtree.h"
#include "cap_ipv4_ntrie.h"
#include <pthread.h>
#include <time.h>
#if 0
MODULE_DESCRIPTION("IPv4 Address Store & Search Module");
MODULE_AUTHOR("Husong ,husong@husong.com 2010-02-24");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
#endif

static unsigned long   MemoryPoolSize1=1024*1024*32;
static unsigned long   MemoryPoolSize2=1024*1024*1;
static struct rb_root* g_table=NULL;
//static rwlock_t g_ipv4status_lock;
static pthread_mutex_t g_ipv4status_lock;


unsigned long get_ipv4_status(unsigned char*ip)
{
	unsigned long flags;
	unsigned long status=0;
	struct my_rbnode*mynode=NULL;

	//read_lock_irqsave(&g_ipv4status_lock,flags);
        pthread_mutex_lock(&g_ipv4status_lock);
	mynode=hash_rbtree_search(g_table,ip);
	status=mynode?mynode->attr.status:multi_ntrie_get_status(ip);
	//read_unlock_irqrestore(&g_ipv4status_lock,flags);
        pthread_mutex_unlock(&g_ipv4status_lock);
	return status;
}

void get_ipv4_all(struct trans_ioctl_ipv4 *attr)
{//get ipv4 address's flow and status
	unsigned long flags;
	
	struct my_rbnode* mynode=NULL;
	//read_lock_irqsave(&g_ipv4status_lock,flags);
        pthread_mutex_lock(&g_ipv4status_lock);
	mynode=hash_rbtree_search(g_table,attr->net);
	if(mynode){
		memcpy(attr, &(mynode->attr), sizeof(struct trans_ioctl_ipv4));
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
	//read_unlock_irqrestore(&g_ipv4status_lock,flags);
        pthread_mutex_unlock(&g_ipv4status_lock);
}




int set_ipv4_status(unsigned char * netprefix,unsigned long prefixlen,unsigned long status)
{
	unsigned long flags;

	int ret=0;
//	
	//write_lock_irqsave(&g_ipv4status_lock,flags);
        pthread_mutex_lock(&g_ipv4status_lock);
//	
	if(prefixlen==32){
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
	//write_unlock_irqrestore(&g_ipv4status_lock,flags);
        pthread_mutex_unlock(&g_ipv4status_lock);
//
	return ret;
}


static  struct trans_ioctl_ipv4 * __get_ipv4_status_and_flow_ptr(unsigned char*ip,unsigned long *status)
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

unsigned long transfer_test_and_merge_flow4(struct iphdr*ipv4h)
{
	unsigned long flags;

	struct trans_ioctl_ipv4 *sipnode=NULL;
	struct trans_ioctl_ipv4 *dipnode=NULL;
	unsigned long scntl;
	unsigned long dcntl;
	unsigned long ok_to_go;
	unsigned short payload_len;

//
	//write_lock_irqsave(&g_ipv4status_lock,flags);
        pthread_mutex_lock(&g_ipv4status_lock);
//	
	sipnode = __get_ipv4_status_and_flow_ptr((unsigned char*)&(ipv4h->saddr),&scntl);
	dipnode = __get_ipv4_status_and_flow_ptr((unsigned char*)&(ipv4h->daddr),&dcntl);
	ok_to_go=transfer_test_with_status(scntl, dcntl);
	payload_len=ntohs(ipv4h->tot_len);

/*	
	printk(KERN_ALERT"OK:[%d],scntl:[0x%X],dcntl:[0x%X],saddr:[%d.%d.%d.%d],daddr:[%d.%d.%d.%d]\n",ok_to_go, scntl,dcntl,
		((unsigned char*)(&ipv4h->saddr))[0], 
		((unsigned char*)(&ipv4h->saddr))[1],
		((unsigned char*)(&ipv4h->saddr))[2],
		((unsigned char*)(&ipv4h->saddr))[3],
		((unsigned char*)(&ipv4h->daddr))[0],
		((unsigned char*)(&ipv4h->daddr))[1],
		((unsigned char*)(&ipv4h->daddr))[2],
		((unsigned char*)(&ipv4h->daddr))[3]);
*/

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
//	
	//write_unlock_irqrestore(&g_ipv4status_lock,flags);
        pthread_mutex_unlock(&g_ipv4status_lock);
//

	return ok_to_go;
}

int print_ipv4_memory_info()
{
	unsigned long flags;

	//write_lock_irqsave(&g_ipv4status_lock,flags);
        pthread_mutex_lock(&g_ipv4status_lock);

	multi_ntrie_print_memory();
	hash_rbtree_print_memory();

	//write_unlock_irqrestore(&g_ipv4status_lock,flags);
        pthread_mutex_unlock(&g_ipv4status_lock);
	
	return 0;
}

int cap_ipv4_ss_init(void)
{
	int result;

	//rwlock_init(&g_ipv4status_lock);
        pthread_mutex_init(&g_ipv4status_lock,NULL);
	
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
void cap_ipv4_ss_exit(void)
{
	hash_rbtree_free(&g_table);
	multi_ntrie_free();
}

