#ifndef CAP_IPV4_NTRIE_H
#define CAP_IPV4_NTRIE_H


int  
multi_ntrie_init(unsigned long MemoryPoolSize1,unsigned long MemoryPoolSize2);

void 
multi_ntrie_free(void);

void 
multi_ntrie_print_memory(void);

unsigned long 
multi_ntrie_get_status(register unsigned char *ip/*[4]*/);

int 
multi_ntrie_set_status(register unsigned char*netprefix , unsigned long prefixlength, unsigned long status);




#endif // CAP_IPV4_NTRIE_H

