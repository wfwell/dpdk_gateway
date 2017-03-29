#include <syslog.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "control.h"
#include "nas_parameters.h"
#include "cap_trans.h"
#include "cap_ipv4_ss.h"
#include "cap_ipv6_ss.h"
//#include "cap_redirect.h"
#include <pthread.h>

/**
* Interface for controlling kernel modules
* Reviewed by huangyj@cernet.com licg@CERNET 2003-4-26
* Add syslog support,NP support
* Use new ip attribute settings.
**/
struct transfer_config_status {
	pthread_mutex_t   lock;
	unsigned long	  trans_up;
	char	          dev_inner[128];
	char              dev_outer[128];
};

static struct transfer_config_status 	real_info;
static struct transfer_config_status *  info=&real_info;
static int    control_device_socket;


/*
 * Open socket, and init struct
 */
int  InitDevice()
{  
    /* 
	control_device_socket=socket(AF_TRANS,0,htons(ETH_P_ALL));
	if(control_device_socket<0) {
		syslog(LOG_ERR,"Create device error.\n");
		return -1;
	}
   */
    memset(info,0,sizeof(*info));	
    info->trans_up = 0;
    pthread_mutex_init(&info->lock,NULL);
    //init_eal();
    if(cap_ipv4_ss_init()!=0){
         printf("cap_ipv4_ss_init() fail\n");
         exit(-1);
    }
    if(cap_ipv6_ss_init()!=0){
         printf("cap_ipv6_ss_init() fail\n");
         exit(-1);
    }
    //init_cap_redirect();    
    return 0;
   
}

/*
 * Close socket, release devices
 */
void CloseDevice()
{
    /*
	close(control_device_socket);
	syslog(LOG_ERR,"Device Closed.\n");
	control_device_socket=-1;
    */
     
}

/* Bring up the system */
int StartTransfer()
{
   #if 0
	int err;

	err=ioctl(control_device_socket,CAP_TRANS_IOCTL_UP,NULL);
	
	if(err != 0){
		syslog(LOG_ERR,"Startup device error.\n");
		return err;
	}
   #endif
        pthread_mutex_lock(&info->lock);
        info->trans_up = 1;
        pthread_mutex_unlock(&info->lock);
	return 0;
}

/*
 * Relase in kernel
 */
int StopTransfer()
{
     /*
	int err;

	err=ioctl(control_device_socket,CAP_TRANS_IOCTL_DOWN,NULL);
	
	if(err != 0){
		syslog(LOG_ERR,"Shutdown device error.\n");
		return err;
	}
     */
        pthread_mutex_lock(&info->lock);
        info->trans_up = 0;
        pthread_mutex_unlock(&info->lock);
	return 0;
}


int SetTransferDevice(char*devx,char*devy)
{
        char shell_command[256]={0};

	strcpy(info->dev_inner,devx);
	strcpy(info->dev_outer,devy);
	sprintf(shell_command,
		"modprobe %s ; modprobe %s ; ifconfig %s promisc up ; ifconfig %s promisc up ;",
		devx,devy,devx,devy);

	system(shell_command);
	//return ioctl(control_device_socket,CAP_TRANS_IOCTL_SET_DEVICE,&iopara);
        return 0;
}


int GetTransferConfig(trans_ioctl_transfer * input)
{
        pthread_mutex_lock(&info->lock);	
        input->trans_up=info->trans_up;
        strcpy(input->inner, info->dev_inner);
        strcpy(input->outer, info->dev_outer);
        pthread_mutex_unlock(&info->lock); 
	//return ioctl(control_device_socket,CAP_TRANS_IOCTL_GET_DEVICE,transfer_status);
        return 0;
}
int SetIPv6Status(unsigned char * netprefix,unsigned long prefixlen,unsigned long status )
{
	int err;
	//err = ioctl(control_device_socket,CAP_TRANS_IOCTL_IPV6_SET,input);
        err=set_ipv6_status(netprefix ,prefixlen,status);
	return err;
}


unsigned long GetIPv6Status(unsigned char * netprefix)
{
	int status;
	//err = ioctl(control_device_socket,CAP_TRANS_IOCTL_IPV6_GET,input);
        status=get_ipv6_status(netprefix);
	return status;
}

int GetIPv6AllStatus(struct trans_ioctl_ipv6 * ipv6_set)
{
        get_ipv6_all(ipv6_set);
        return 0;
	//return  ioctl(control_device_socket,CAP_TRANS_IOCTL_IPV6_GET_ALL,ipv6_set);
}
int  SetRedirect(struct trans_ioctl_redirect *input)
{
	//return  ioctl(control_device_socket,CAP_TRANS_IOCTL_SET_REDIRECT,input);
        return 0;
}

int  GetRedirect(struct trans_ioctl_redirect *output)
{
	//return  ioctl(control_device_socket,CAP_TRANS_IOCTL_GET_REDIRECT,output);
        return 0;
}

int SetRedirectUrl(char*url)
{
      /*
	int err;
	
	struct trans_ioctl_redirect input;

	err=GetRedirect(&input);
	if(err<0)
		return err;

	strcpy(input.url,url);

	err=SetRedirect(&input);
	if(err<0)
		return err;

	return 0;	
     */
      return 0;
}


int SetRedirectTimeout(int timeout)
{
     /*
	int err;
	
	struct trans_ioctl_redirect input;

	err=GetRedirect(&input);
	if(err<0)
		return err;

	input.timeout=timeout;

	err=SetRedirect(&input);
	if(err<0)
		return err;

	return 0;	
     */
     return 0;
}



int SetIPv4Status(unsigned char * netprefix,unsigned long prefixlen,unsigned long status )

{
         //return ioctl(control_device_socket,CAP_TRANS_IOCTL_IPV4_SET,input);
         return set_ipv4_status(netprefix,prefixlen,status);

}


unsigned long GetIPv4Status(unsigned char * netprefix)
{
         int status;
         //err = ioctl(control_device_socket,CAP_TRANS_IOCTL_IPV4_GET,input);
         status=get_ipv4_status(netprefix);
         return status;

}


int GetIPv4AllStatus(struct trans_ioctl_ipv4 * ipv4_set)

{
         get_ipv4_all(ipv4_set);
         return 0;
         //return  ioctl(control_device_socket,CAP_TRANS_IOCTL_IPV4_GET_ALL,ipv4_set);
}


int filter_invalid_ipv6_address(unsigned char * input,int ipv6_count,unsigned char * output)
{
	int left=0;
	
	for (int i=0;i<ipv6_count;i++){
		if(!is_address_valid(ipv6_config_get(input+(i*16)).attribute.number_value))//static  attribute from config file
			continue;
		if(!is_address_valid(GetIPv6Status(input+(i*16))))//dynamic status from kernel module
			continue;

		struct in6_addr swap;
		memcpy(&swap,input+(i*16),sizeof(swap));
		memcpy(output+(left*16),&swap,sizeof(swap));
		left++;
	}
	
	return left;
}

int filter_online_ipv6_address(unsigned char * input,int ipv6_count,unsigned char * output)
{
	int left=0;
	
	for (int i=0;i<ipv6_count;i++){
		if(has_address_logined_now(ipv6_config_get(input+(i*16)).attribute.number_value)==1)//static  attribute from config file
			continue;
		if(has_address_logined_now(GetIPv6Status(input+(i*16))) == 1)//dynamic status from kernel module
			continue;

		struct in6_addr swap;
		memcpy(&swap,input+(i*16),sizeof(swap));
		memcpy(output+(left*16),&swap,sizeof(swap));
		left++;
	}
	
	return left;
}

int filter_invalid_ipv4_address(unsigned char * input,int ipv4_count,unsigned char * output)
{
	int left=0;
	
	for (int i=0;i<ipv4_count;i++){
		if(!is_address_valid(ipv4_config_get(input+(i*4)).attribute.number_value))//static  attribute from config file
			continue;
		if(!is_address_valid(GetIPv4Status(input+(i*4))))//dynamic status from kernel module
			continue;

		uint32_t swap;
		memcpy(&swap, input+(i*4), sizeof(swap));
		memcpy(output+(left*4), &swap, sizeof(swap));
		left++;
	}
	
	return left;
}

int filter_online_ipv4_address(unsigned char * input,int ipv4_count,unsigned char * output)
{
	int left=0;
	
	for (int i=0;i<ipv4_count;i++){
		if(has_address_logined_now(ipv4_config_get(input+(i*4)).attribute.number_value)==1)//static  attribute from config file
			continue;
		if(has_address_logined_now(GetIPv6Status(input+(i*4))) == 1)//dynamic status from kernel module
			continue;

		uint32_t swap;
		memcpy(&swap, input+(i*4), sizeof(swap));
		memcpy(output+(left*4), &swap, sizeof(swap));
		left++;
	}
	
	return left;
}
