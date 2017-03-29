#ifndef CAP_IPV6_MULTINTRIE_H
#define CAP_IPV6_MULTINTRIE_H


int  
multi_ntrie_init(unsigned long MemoryPoolSize1,unsigned long MemoryPoolSize2);

void 
multi_ntrie_free(void);

void 
multi_ntrie_print_memory(void);

unsigned long 
multi_ntrie_get_status(register unsigned char *ip/*[16]*/);

int 
multi_ntrie_set_status(register unsigned char*netprefix , unsigned long prefixlength, unsigned long status);




#endif // CAP_IPV6_MULTINTRIE_H

