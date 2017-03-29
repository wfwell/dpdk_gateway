#ifndef TRANS_CONTROL_H
#define TRANS_CONTROL_H
extern "C" {
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "cap_trans.h"


int  
	InitDevice();
void 
	CloseDevice();

int 
	StartTransfer();
int 
	StopTransfer();
int 
	SetTransferDevice(char*devx,char*devy);
int 
	GetTransferConfig(trans_ioctl_transfer * transfer_status);


int 
	SetIPv6Status(unsigned char * netprefix,unsigned long prefixlen,unsigned long status );
unsigned long 
	GetIPv6Status(unsigned char * netprefix);
int 
	GetIPv6AllStatus(struct trans_ioctl_ipv6 * ipv6_set);


int  
	SetRedirect(struct trans_ioctl_redirect *input);
int  
	GetRedirect(struct trans_ioctl_redirect *output);
int 
	SetRedirectUrl(char*url);
int 
	SetRedirectTimeout(int timeout);

int SetIPv4Status(unsigned char * netprefix,unsigned long prefixlen,unsigned long status );
unsigned long GetIPv4Status(unsigned char * netprefix);
int GetIPv4AllStatus(struct trans_ioctl_ipv4 * ipv4_set);


int filter_invalid_ipv6_address(unsigned char * input,int ipv6_count,unsigned char * output);
int filter_online_ipv6_address(unsigned char * input,int ipv6_count,unsigned char * output);

int filter_invalid_ipv4_address(unsigned char * input,int ipv4_count,unsigned char * output);
int filter_online_ipv4_address(unsigned char * input,int ipv4_count,unsigned char * output);


}
#endif

