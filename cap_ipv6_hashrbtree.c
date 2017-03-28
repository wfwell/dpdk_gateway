
#include "cap_ipv6_hashrbtree.h"
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////




static  int compare_key(register unsigned long *pv1,register unsigned long*pv2)
{
	register unsigned long i;
	
	for(i=0;i<4;i++)
	{
		if		(*pv1>*pv2)
			return 1;
		else if (*pv1<*pv2)
			return -1;
		
		pv1++;
		pv2++;
	}

	return 0;
}


static  unsigned long get_hash(unsigned long*ip)
{
	return (ip[3]^ip[2])%(HASHTABLESIZE-1);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static  struct my_rbnode* my_rbtree_search (struct rb_root* root, unsigned char*key) 
{
	struct rb_node   * node; 
	struct my_rbnode * mynode; 

	int compare;

	
	node = root->rb_node; 
	while (node) 
	{
		mynode = rb_entry (node, struct my_rbnode, node); 
		
		compare=compare_key((long unsigned int *)key,(long unsigned int *)mynode->attr.net);
		if      (compare>0) 
			node = node->rb_left; 
		else if (compare<0) 
			node = node->rb_right; 
		else
			return mynode;/* found it */ 
	}

	return NULL; 
}


static  int my_rbtree_insert (struct rb_root* root, unsigned char*key,unsigned long value,int overwrite) 
{
	int compare;
	struct rb_node * parent=NULL; 
	struct my_rbnode* item=NULL;
	struct my_rbnode* mynode;

	struct rb_node **link=&(root->rb_node);

	while (*link) 
	{
		parent = *link; 
		mynode = rb_entry(parent, struct my_rbnode, node); 

		compare=compare_key((long unsigned int *)key,(long unsigned int *)mynode->attr.net);

		if      (compare>0) 
			link = &((*link)->rb_left); 
		else if (compare<0) 
			link = &((*link)->rb_right); 
		else 
		{//key exists.
			if(overwrite){
				mynode->attr.status=value;
				return 0;
			}
			else{
				return -EEXIST;
			}
		}
	}

	item=(struct my_rbnode*)malloc(sizeof(struct my_rbnode));
	if(item==NULL)
		return -ENOMEM;

	memset(item,0,sizeof(struct my_rbnode));
	memcpy(item->attr.net,key,NETKEYLENGTHIPV6);
	item->attr.status=value;

	/* Put the new node there */ 
	rb_link_node(&(item->node), parent, link); 
	rb_insert_color(&(item->node), root); 

	return 0;
}

static  void my_rbtree_delete (struct rb_root* root, unsigned char*key) 
{
	struct my_rbnode* mynode; 
	mynode = my_rbtree_search (root, key); 
	if (mynode) 
	{
		rb_erase (&(mynode->node), root);
		free(mynode);
	}
}

static void my_rbtree_init(struct rb_root* root)
{
	root->rb_node=NULL;
}

static void my_rbtree_free(struct rb_root* root)
{
	struct rb_node*node;
	struct my_rbnode*mynode;

	while( !RB_EMPTY_ROOT(root) )
	{
		node=root->rb_node;
		mynode = rb_entry(node, struct my_rbnode, node); 

		rb_erase (&(mynode->node), root);
		free(mynode);
	}
}


////////////////////////////////////////////////////////////////////////////////
// hash+rbtree
////////////////////////////////////////////////////////////////////////////////


int hash_rbtree_init(struct rb_root**ptable)
{
	int i;
	struct rb_root * table;

	table=(struct rb_root*)malloc(sizeof(struct rb_root)*HASHTABLESIZE);
	if(table==NULL)
		return -1;
        memset(table,0,sizeof(struct rb_root)*HASHTABLESIZE);

	for(i=0;i<HASHTABLESIZE;i++)
		my_rbtree_init(table+i);

	*ptable=table;

	return 0;
}

void hash_rbtree_free(struct rb_root**ptable)
{
	int i;
	struct rb_root * table;

	table=*ptable;

	if(table)
	{
		for(i=0;i<HASHTABLESIZE;i++)
			my_rbtree_free(table+i);
		free(table);
		*ptable=NULL;
	}
}


inline int hash_rbtree_insert(struct rb_root*table ,unsigned char*ip,unsigned long value,int overwrite)
{
	return my_rbtree_insert(table+get_hash((long unsigned int *)ip),ip,value,overwrite);
}

inline void hash_rbtree_delete(struct rb_root*table ,unsigned char*ip)
{
	my_rbtree_delete(table+get_hash((long unsigned int *)ip),ip);
}

inline struct my_rbnode* hash_rbtree_search(struct rb_root*table ,unsigned char*ip)//,unsigned long *value)
{
	return my_rbtree_search(table+get_hash((long unsigned int *)ip),ip);
}

void hash_rbtree_print_memory(void)
{
	printf("\n(Store2) begin\n");
	
	printf("Hashtable\n");
	printf("\tSize:%d,\tMemory:%lu KB\n",
		HASHTABLESIZE,
		sizeof(struct rb_root)*HASHTABLESIZE/1024);

	printf("(Store2) end .\n");

}

