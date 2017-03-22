#ifndef CAP_IPV4_HASHRBTREE_H
#define CAP_IPV4_HASHRBTREE_H


//#include <linux/kernel.h>
/*
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
#include <linux/rbtree.h>
#include "cap_trans.h"
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
//#include <linux/ioctl.h> 
#include <sys/ioctl.h>
#include "rbtree.h"
#include <stdint.h>
#include <asm/errno.h>
#include "cap_trans.h"
//#include "/usr/src/kernels/3.10.0-327.36.3.el7.x86_64/include/linux/gfp.h"
//#include "/usr/src/kernels/3.10.0-327.36.3.el7.x86_64/include/linux/mmdebug.h"
#define HASHTABLESIZE 65536
////////////////////////////////////////////////////////////////////////////////
// rbtree
////////////////////////////////////////////////////////////////////////////////

struct my_rbnode{
  	struct rb_node    node; 
	struct trans_ioctl_ipv4 attr;
};


int 
hash_rbtree_init (struct rb_root**ptable);

void 
hash_rbtree_free(struct rb_root**ptable);

void 
hash_rbtree_print_memory(void);

int 
hash_rbtree_insert (struct rb_root*table ,unsigned char*ip,unsigned long  value,int overwrite);

void 
hash_rbtree_delete(struct rb_root*table ,unsigned char*ip);

struct my_rbnode* 
hash_rbtree_search (struct rb_root*table ,unsigned char*ip);


#endif //CAP_IPV4_HASHRBTREE_H

