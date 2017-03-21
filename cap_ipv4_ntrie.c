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
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "list.h"
#include "cap_trans.h"
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////


typedef struct ipv4status
{
	struct ipv4status *children;
	unsigned long      status;
} IPV4STATUS;


typedef struct ipv4status_list_head
{
	struct ipv4status_list_head *next;
	struct ipv4status_list_head *prev;
        IPV4STATUS                  *block;
	unsigned long 		    queue_len;
}IPV4STATUS_LIST_HEAD;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#define BLOCK_MASK_ADDRESS       0xFFFFFFFF
#define BLOCK_MASK_RESERVED     0x00000002
#define BLOCK_MASK_SIZE              0x00000001

#define BLOCK_ADDRESS(X)        ((IPV4STATUS*)(    ((unsigned long)X) &  BLOCK_MASK_ADDRESS    ))
#define BLOCK_SIZE_SET_65536(X) ((IPV4STATUS*)(    ((unsigned long)X) |  BLOCK_MASK_SIZE       ))
#define BLOCK_SIZE_SET_256(X)   ((IPV4STATUS*)(    ((unsigned long)X) &(~BLOCK_MASK_SIZE)      ))

#define BLOCK____SIZE(X)        ( (((unsigned long)X)&BLOCK_MASK_SIZE)?65536:256)
#define BLOCK_SIZE_IS_65536(X)  (  ((unsigned long)X)&BLOCK_MASK_SIZE           )
#define BLOCK_SIZE_IS_256(X)    (!(((unsigned long)X)&BLOCK_MASK_SIZE)          )

#define MAXIMUM_HIGH_LAYERS     1
#define MAXIMUM_HIGH_BITS       16
#define BITS_PER_HIGH_LAYER     16
#define BITS_PER_LOW_LAYER      8

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static IPV4STATUS  g_treeipv4status={NULL,IPVO_DEFAULT};

static IPV4STATUS_LIST_HEAD g_listfreeblock_256={&g_listfreeblock_256,&g_listfreeblock_256,NULL,0};

static IPV4STATUS_LIST_HEAD g_listfreeblock_65536={&g_listfreeblock_65536,&g_listfreeblock_65536,NULL,0};

static IPV4STATUS_LIST_HEAD g_listfreelink={&g_listfreelink,&g_listfreelink,NULL,0};//only for free blocks



////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static IPV4STATUS_LIST_HEAD* from_size_to_list(unsigned long size)
{
	switch(size)
	{
		case 256:
			return &g_listfreeblock_256;
		case 65536:
			return &g_listfreeblock_65536;
		default:
			return NULL;
	}

	return NULL;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static  IPV4STATUS * freeblock_get_head(unsigned long size)
{
	IPV4STATUS_LIST_HEAD * plink;
	IPV4STATUS * pblock;
	IPV4STATUS_LIST_HEAD * free_block_list=from_size_to_list(size);
	
	if(list_empty((struct list_head *)free_block_list))
		return NULL;

	plink=free_block_list->next;
	pblock=plink->block;
	plink->block=NULL;

	list_del((struct list_head *)plink);
	list_add((struct list_head *)plink,(struct list_head *)&g_listfreelink);
	free_block_list->queue_len--;
	g_listfreelink.queue_len++;

	return pblock;
}



static void freeblock_put_tail(IPV4STATUS*parent)
{
	IPV4STATUS_LIST_HEAD * plink;
	
	//Now block size may be 256,65536 .
	//It may be other values in the future.
	IPV4STATUS_LIST_HEAD * free_block_list;


	if(!BLOCK_ADDRESS(parent->children))
		return ;

	free_block_list=from_size_to_list(BLOCK____SIZE(parent->children));
	plink=g_listfreelink.next;


	list_del((struct list_head *)plink);
	list_add_tail((struct list_head *)plink,(struct list_head *)free_block_list);
	free_block_list->queue_len++;
	g_listfreelink.queue_len--;

	plink->block=parent->children;
	parent->children=NULL;
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
static  void free_tree(IPV4STATUS * node)
{
	unsigned long i;
	IPV4STATUS_LIST_HEAD*pcurrent;
	IPV4STATUS_LIST_HEAD*ptail_65536=g_listfreeblock_65536.prev;
	IPV4STATUS_LIST_HEAD*ptail_256=g_listfreeblock_256.prev;


	freeblock_put_tail(node);


	for(pcurrent=ptail_65536->next;  pcurrent != &g_listfreeblock_65536; pcurrent=pcurrent->next)
	    for(i=0;i<65536;i++)
			freeblock_put_tail(BLOCK_ADDRESS(pcurrent->block)+i);


	for(pcurrent=ptail_256->next;    pcurrent != &g_listfreeblock_256;   pcurrent=pcurrent->next)
	    for(i=0;i<256;i++)
			freeblock_put_tail(BLOCK_ADDRESS(pcurrent->block)+i);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
static  IPV4STATUS * alloc_children(IPV4STATUS *parent,unsigned long size)
{
	unsigned long i;
	IPV4STATUS *pblock=freeblock_get_head(size);
	IPV4STATUS *pblockaddress=BLOCK_ADDRESS(pblock);

	if(!pblockaddress)
	{
		printf("alloc_children : failed when freeblock_get_head(%lu).\n",size);
		return NULL;
	}


	for(i=0;i<size;i++)
	{
		(pblockaddress+i)->status=parent->status;
		(pblockaddress+i)->children=NULL;
	}


	parent->children=pblock;
	
	if(size==65536){
		parent->children=BLOCK_SIZE_SET_65536(parent->children);
	}
	else{
		parent->children=BLOCK_SIZE_SET_256(parent->children);
	}
	
	return parent->children;
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
int multi_ntrie_init(unsigned long MemoryPoolSize1,unsigned long MemoryPoolSize2)
{
	int i;

//
	for(i=0;i<MemoryPoolSize1/(sizeof(IPV4STATUS)*256);i++)
	{
		IPV4STATUS_LIST_HEAD *ptail = malloc(sizeof(IPV4STATUS_LIST_HEAD));
                memset(ptail,0,sizeof(IPV4STATUS_LIST_HEAD));
		if(!ptail)
		{
			printf("init_ipv4status : failed when malloc IPV4STATUS_LIST_HEAD at %d. \n",i);		
			return -1;
		}
		
		ptail->block=(IPV4STATUS*)malloc(sizeof(IPV4STATUS)*256);
                memset(ptail->block,0,sizeof(IPV4STATUS)*256);
		if(!ptail->block)
		{
			printf("init_ipv4status : failed when malloc  IPV4STATUS * 256 at %d. \n",i);		
			free(ptail);
			return -1;
		}

		list_add_tail((struct list_head *)ptail,(struct list_head *)&g_listfreeblock_256);
		g_listfreeblock_256.queue_len++;
	}

//
	for(i=0;i<MemoryPoolSize2/(sizeof(IPV4STATUS)*65536);i++)
	{
		IPV4STATUS_LIST_HEAD *ptail = malloc(sizeof(IPV4STATUS_LIST_HEAD));
                memset(ptail,0,sizeof(IPV4STATUS_LIST_HEAD));
		if(!ptail)
		{
			printf("init_ipv4status : failed when malloc IPV4STATUS_LIST_HEAD at %d. \n",i); 	
			return -1;
		}
		
		ptail->block=(IPV4STATUS*)malloc(sizeof(IPV4STATUS)*65536);
                memset(ptail->block,0,sizeof(IPV4STATUS)*65536);
		if(!ptail->block)
		{
			printf("init_ipv4status : failed when malloc  IPV4STATUS * 65536 at %d. \n",i);		
			free(ptail);
			return -1;
		}

		list_add_tail((struct list_head *)ptail,(struct list_head *)&g_listfreeblock_65536);
		g_listfreeblock_65536.queue_len++;
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void multi_ntrie_free(void)
{
	IPV4STATUS_LIST_HEAD*pcurrent=NULL;

	free_tree(&g_treeipv4status);

	while(  ! list_empty((struct list_head *)&g_listfreeblock_256) )
	{
		pcurrent=g_listfreeblock_256.next;
		list_del((struct list_head *)pcurrent);
		free(BLOCK_ADDRESS(pcurrent->block));
		free(pcurrent);
	}

	while(  ! list_empty((struct list_head *)&g_listfreeblock_65536) )
	{
		pcurrent=g_listfreeblock_65536.next;
		list_del((struct list_head *)pcurrent);
		free(BLOCK_ADDRESS(pcurrent->block));
		free(pcurrent);
	}

	while(  ! list_empty((struct list_head *)&g_listfreelink) )
	{
		pcurrent=g_listfreelink.next;
		list_del((struct list_head *)pcurrent);
		free(pcurrent);
	}
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
 unsigned long multi_ntrie_get_status(register unsigned char *ip/*[16]*/)
{
       register IPV4STATUS *p=&g_treeipv4status;
	register unsigned long index;

	while(BLOCK_ADDRESS(p->children))
	{
		index  = (*ip);
		ip++;
		if(BLOCK_SIZE_IS_65536(p->children))
		{
			index <<= 8;
			index += (*ip);
			ip++;

			p=BLOCK_ADDRESS(p->children) + index;
		}
		else//(BLOCK_SIZE_IS_256(p->children))
		{
			p=BLOCK_ADDRESS(p->children) + index;
		}
	}

	return p->status;
}



////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
 int multi_ntrie_set_status(register unsigned char*netprefix , unsigned long prefixlength, unsigned long status)
{
	IPV4STATUS *p=&g_treeipv4status;

	unsigned long  ilayer,i;
	unsigned long  from,to;
	unsigned char  index1;
	unsigned short index2;


	unsigned long high_bits    =prefixlength>=MAXIMUM_HIGH_BITS?MAXIMUM_HIGH_BITS:prefixlength;//if prefixlength=24
	unsigned long high_layers  =high_bits/BITS_PER_HIGH_LAYER;
	unsigned long high_leftbits=high_bits%BITS_PER_HIGH_LAYER;


	unsigned long low_bits     =prefixlength-high_bits;
	unsigned long low_layers   =low_bits/BITS_PER_LOW_LAYER;
	unsigned long low_leftbits =low_bits%BITS_PER_LOW_LAYER;
	



	// step over 16 bits per layer
	if(high_bits){//>0
	
		for(ilayer=0;ilayer<high_layers;ilayer++){// /0 ,/16 
			if(BLOCK_ADDRESS(p->children)==NULL)
				if(BLOCK_ADDRESS(alloc_children(p, 65536))==NULL)
					goto nomemory;
              
            
			index2 =  (((unsigned short)netprefix[ilayer*2])<<8) + ((unsigned short)netprefix[ilayer*2+1]);
			
			p=BLOCK_ADDRESS(p->children)+ index2 ;
		}

		if(high_leftbits){// /1-15

			if(BLOCK_ADDRESS(p->children)==NULL)
				if(BLOCK_ADDRESS(alloc_children(p, 65536))==NULL)
					goto nomemory;


			from = (((unsigned short)netprefix[ilayer*2])<<8) + ((unsigned short)netprefix[ilayer*2+1]);
			from&= 0xFFFF << (BITS_PER_HIGH_LAYER-high_leftbits) ;

			to   =from;
			to  |= 0xFFFF >> high_leftbits;

			for(i=from;i<=to;i++){
				free_tree(BLOCK_ADDRESS(p->children)+i);
				(BLOCK_ADDRESS(p->children)+i)->status=status;
			}

			return 0;
		}
	}


	// step over 8 bits per layer
	if(low_bits){//>/16
	
		for(ilayer=0;ilayer<low_layers;ilayer++){// /24
			
			if(BLOCK_ADDRESS(p->children)==NULL)
				if(BLOCK_ADDRESS(alloc_children(p, 256))==NULL)
					goto nomemory;


			index1 = netprefix[2+ilayer];
			
			p=BLOCK_ADDRESS(p->children)+ index1 ;
		}

		if(low_leftbits){//  17-23,25-31
			if(BLOCK_ADDRESS(p->children)==NULL)
				if(BLOCK_ADDRESS(alloc_children(p, 256))==NULL)
					goto nomemory;

			from = netprefix[2+ilayer];
			from&= 0xFF << (BITS_PER_LOW_LAYER-low_leftbits) ;

			to   = from;
			to  |= 0xFF >> low_leftbits;

			for(i=from;i<=to;i++){
				free_tree(BLOCK_ADDRESS(p->children)+i);
				(BLOCK_ADDRESS(p->children)+i)->status=status;
			}

			return 0;
		}
		
	}
	

	// 32,it stored in hash+rbtree.
	free_tree(p);
	p->status=status;

	return 0;
	
nomemory:
	
	return -1;
}


void multi_ntrie_print_memory(void)
{

}
