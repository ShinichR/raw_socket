#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/filter.h>
#include <sys/ioctl.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>


//#include <os-Linux/util.h>

// XXX
static struct ifreq ifr_cleanup;
static unsigned char the_mac[6];

static void
raw_cleanup(void)
{
    int s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
	perror("raw_cleanup: socket failed");
	return;
    }

    if (ioctl(s, SIOCSIFFLAGS, &ifr_cleanup) < 0)
	printf("raw_cleanup: ioctl error: %s\n", strerror(errno));

    close(s);
}

static int get_device_mac()
{
	int i, datalen,frame_length, sd, bytes;
    char *interface="eth0";;
    uint8_t data[128];
    uint8_t dst_mac[6];;
    uint8_t ether_frame[128];
    struct sockaddr_ll device;
    struct ifreq ifr;
    
  
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }
  
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("ioctl() failed to get source MAC address ");
        return 0;
    }
    close (sd);
    memcpy (the_mac, ifr.ifr_hwaddr.sa_data, 6);
}
static int
raw_enable_permisc(int s, const char *iface_alias)
{
    struct ifreq ifr;
    struct packet_mreq pr;

    strncpy(ifr.ifr_name, iface_alias, IFNAMSIZ);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
	printf("ioctl error: %s", strerror(errno));
	return -1;
    }

    // why doesn't the 'new' way work?
    memset(&pr, 0, sizeof(pr));
    pr.mr_ifindex = ifr.ifr_ifindex;
    pr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		   &pr, sizeof(pr) < 0)) {
	
	// try old fashion way
	struct ifreq ifr2;
	strncpy(ifr2.ifr_name, iface_alias, IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, &ifr2) < 0) {
	    printf("ioctl error: %s", strerror(errno));
	    return -1;
	}
	memcpy(&ifr_cleanup, &ifr2, sizeof(ifr_cleanup));
	ifr2.ifr_flags |= IFF_PROMISC;
	if (ioctl(s, SIOCSIFFLAGS, &ifr2) < 0) {
	    printf("ioctl error: %s", strerror(errno));
	    return -1;
	}
	atexit(raw_cleanup);
    }

    return 0;
}

static int
raw_enable_filter(int s, const unsigned char *mac_addr)
{
    uint32_t mac0 = 0;
    uint32_t mac1 = 0;
    struct sock_filter BPF_code[10];
    struct sock_fprog filter; 
    
    BPF_code[0] = (struct sock_filter) { 0x28, 0, 0, 0x0000000c };
    BPF_code[1] = (struct sock_filter) { 0x15, 1, 0, 0x0000980b };
	BPF_code[2] = (struct sock_filter) { 0x15, 0, 1, 0x0000980a };
    BPF_code[3] = (struct sock_filter) { 0x6, 0, 0, 0x0000ffff };
    BPF_code[4] = (struct sock_filter) { 0x6, 0, 0, 0x00000000 };
  
    filter.len = 5;
    filter.filter = BPF_code;
	
    if(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, 
		  &filter, sizeof(filter)) < 0) {
		printf("setsockopt error: %s\n", strerror(errno));
		return -1;
    }

    return 0;
}

static int
raw_socket(const char *iface_alias, const unsigned char *mac_addr)
{
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int s, tmp;
    s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
	perror("raw_socket");
	return s;
    }
    
    /* a temporary socket for setuping up the if */
    tmp = socket(PF_INET, SOCK_DGRAM, 0);
    if (tmp < 0) {
	close(s);
	return -errno;
    }
    
    if (raw_enable_filter(s, mac_addr) < 0)
	return -1;
    
    strncpy(ifr.ifr_name, iface_alias, IFNAMSIZ);
    if (ioctl(tmp, SIOCGIFINDEX, &ifr) < 0)
	return -1;
    
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(s, (struct sockaddr *) &sll, sizeof(sll)) < 0)
	return -1;
    
    close(tmp);
    return s;
}


int 
rawsock_mac(unsigned char *buf)
{
    memcpy(buf, the_mac, sizeof(the_mac));
    return 0;
}

int
rawsock_open(const char *name, void *data)
{
    /* XXX no error handling (in any functions) */
    int s, r, flags;
  

	printf("raw_socket in\n");
    s = raw_socket("eth0", the_mac);
	printf("raw_socket out,%d\n",s);
    if (s < 0)
	return -1;
    
    if ((flags = fcntl(s, F_GETFL)) < 0)
	return -errno;
    
    flags |= O_ASYNC | O_NONBLOCK;
    
    if ((r = fcntl(s, F_SETFL, flags)) < 0)
	return -errno;

   // if ((r = fcntl(s, F_SETOWN, util_getpid())) < 0)
	//return -errno;
        
   // if ((r = fcntl(s, F_SETSIG, SIGIO)) < 0)
	//return -errno;

    return s;

}

int
rawsock_tx(int fd, void *buf, unsigned int buf_len)
{
    int r;
  
    
    r = write(fd, buf, buf_len);
    if (r < 0) {
	perror("rawsock_output: write failed");
	return -1;
    } else if (r != buf_len) {
	printf("rawsock_output: write truncate: %d -> %d\n", buf_len, r);
	return r;
    }

    return r;
}

int
rawsock_rx(int fd, void *buf, unsigned int buf_len)
{
    int r;
  
    
    r = read(fd, buf, buf_len);
    if (r < 0) {
	if (errno == EAGAIN)
	    return 0;
	perror("rawsock_output: read failed");
	return -1;
    }

    return r;
}
int recv_980b = 0;
int print(void *buf)
{
	int i;
	int is_myframe = 0;
	char *pbuf = (char *) buf;
	struct ether_header *h1=(struct ether_header*)buf;
   // printf("recv type;%d\n",ntohs(h1->ether_type ));
    if(ntohs(h1->ether_type ) == 0x980b || ntohs(h1->ether_type ) == 0x980a)
   	{
   			/*printf("type=%d\n",ntohs(h1->ether_type ));
   			printf("shost:");
   			for(i = 0 ; i < ETH_ALEN ; i++){
   				printf("%02x:",h1->ether_shost[i]);
   			}
			printf("\n");
			printf("dhost:");
   			for(i = 0 ; i < ETH_ALEN ; i++){
   				printf("%02x:",h1->ether_dhost[i]);
   			}
   			printf("myMac:");
			for(i = 0 ; i < ETH_ALEN ; i++){
   				printf("%02x:",the_mac[i]);
   			}
   			printf("\n");*/
   			
   			if(memcmp(h1->ether_shost,the_mac,6) ==0)
			is_myframe = 1;
			
				
   		    for(i = 0 ; i < ETH_ALEN ; i++){
   				
				//只接收广播包和目的mac是自身的包
				 if((h1->ether_dhost[i] != the_mac[i] && h1->ether_dhost[i] != 0xFF ))
   				 {
   			 		is_myframe = 1;
					//INFO(( "[APP][CWMP][LOSTFRAME] filterd useless packet\n"));
					break;
   				 }
			}
			if(is_myframe)
   			return 0;
			printf("recved:%d\n",++recv_980b);
		
		 //if(length > 26)
			
   			//printf("%u,:%u,\n", pbuf[20]& 255, pbuf[21]& 255);
   			//printf("\nlost Frame:%0x\n",ntohs(h1->ether_type));
   			
   			return 1;
   	}
  
   	return 0;
   
}

int main(){
	int rawsock,recvlen = 0;
	char buf[1024] = {0};
	printf("rawsock_open in\n");
	get_device_mac();
	rawsock = rawsock_open("test","test");
	printf("rawsock_open\n");
	while(1)
	{
		//printf("rawsock_rx\n");
		recvlen = rawsock_rx(rawsock,buf,sizeof(buf));
		if(recvlen >0)print(buf);
		usleep(20000);
	}
	return 0;
}
