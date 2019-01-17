#include <string.h>
#include <jni.h>
#include "it_unipr_netsec_tuntap_TunSocket.h"

#include <fcntl.h>  /* O_RDWR */
#include <string.h> /* memset(), memcpy() */
#include <stdio.h> /* perror(), printf(), fprintf() */
#include <stdlib.h> /* exit(), malloc(), free() */
#include <sys/ioctl.h> /* ioctl() */

/* includes for struct ifreq, etc */
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>


#define __PNAME "TunSocketImp: "

/** Logs an error message. */
void printerr(const char* msg)
{  // append a header to the message
   char* hdr=__PNAME;
   int hdr_len=strlen(hdr);
   int msg_len=strlen(msg);
   char str[hdr_len+msg_len+1];
   strncpy(str,hdr,hdr_len);
   strncpy(str+hdr_len,msg,msg_len);
   str[hdr_len+msg_len]='\0';
   
   #ifdef _WIN32
      int err=WSAGetLastError();
      fprintf(stderr,"%s: %d",str,err);
   #else
      perror(str);
   #endif
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_tuntap_TunSocket_open(JNIEnv* env, jobject obj, jstring name_j)
{
    const char* devname=(*env)->GetStringUTFChars(env,name_j,0); // daddr BEGIN

	struct ifreq ifr;
	int fd, err;

	if ( (fd = open("/dev/net/tun", O_RDWR)) == -1 )
	{	printerr("open /dev/net/tun");
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	strncpy(ifr.ifr_name, devname, IFNAMSIZ);  
	(*env)->ReleaseStringUTFChars(env,name_j,devname); // daddr END

	/* ioctl will use if_name as the name of TUN 
	 * interface to open: "tun0", etc. */
	if ( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) == -1 )
	{	printerr("ioctl TUNSETIFF");
		close(fd);
		exit(1);
	}

	/* After the ioctl call the fd is "connected" to tun device specified
	 * by devname */

	return fd;
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_tuntap_TunSocket_write(JNIEnv* env, jobject obj, jint fd, jbyteArray data_j, jint off, jint len)
{
   jbyte* data=(*env)->GetByteArrayElements(env,data_j,0);
   int nbytes=write(fd,(char*)(data+off),len);
   if(nbytes<0) 
   {	printerr("write()");
		exit(EXIT_FAILURE);
   }
   (*env)->ReleaseByteArrayElements(env,data_j,data,0);
   
   return nbytes;
}


JNIEXPORT jint JNICALL Java_it_unipr_netsec_tuntap_TunSocket_read(JNIEnv* env, jobject obj, jint fd, jbyteArray data_j, jint off)
{
   jsize len=(*env)->GetArrayLength(env,data_j);
   jbyte* data=(*env)->GetByteArrayElements(env,data_j,0);

   int nbytes=read(fd,(char*)(data+off),len);
   if(nbytes<0) 
   {  printerr("recv()");
      exit(EXIT_FAILURE);
   }
   (*env)->ReleaseByteArrayElements(env,data_j,data,0);
   
   return nbytes;
}
