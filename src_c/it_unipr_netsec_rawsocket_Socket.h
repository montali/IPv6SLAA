/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class it_unipr_netsec_rawsocket_Socket */

#ifndef _Included_it_unipr_netsec_rawsocket_Socket
#define _Included_it_unipr_netsec_rawsocket_Socket
#ifdef __cplusplus
extern "C" {
#endif
#undef it_unipr_netsec_rawsocket_Socket_PF_UNSPEC
#define it_unipr_netsec_rawsocket_Socket_PF_UNSPEC 0L
#undef it_unipr_netsec_rawsocket_Socket_PF_UNIX
#define it_unipr_netsec_rawsocket_Socket_PF_UNIX 1L
#undef it_unipr_netsec_rawsocket_Socket_PF_LOCAL
#define it_unipr_netsec_rawsocket_Socket_PF_LOCAL 1L
#undef it_unipr_netsec_rawsocket_Socket_PF_INET
#define it_unipr_netsec_rawsocket_Socket_PF_INET 2L
#undef it_unipr_netsec_rawsocket_Socket_PF_PACKET
#define it_unipr_netsec_rawsocket_Socket_PF_PACKET 17L
#undef it_unipr_netsec_rawsocket_Socket_SOCK_STREAM
#define it_unipr_netsec_rawsocket_Socket_SOCK_STREAM 1L
#undef it_unipr_netsec_rawsocket_Socket_SOCK_DGRAM
#define it_unipr_netsec_rawsocket_Socket_SOCK_DGRAM 2L
#undef it_unipr_netsec_rawsocket_Socket_SOCK_RAW
#define it_unipr_netsec_rawsocket_Socket_SOCK_RAW 3L
#undef it_unipr_netsec_rawsocket_Socket_SOCK_RDM
#define it_unipr_netsec_rawsocket_Socket_SOCK_RDM 4L
#undef it_unipr_netsec_rawsocket_Socket_SOCK_SEQPACKET
#define it_unipr_netsec_rawsocket_Socket_SOCK_SEQPACKET 5L
#undef it_unipr_netsec_rawsocket_Socket_SOCK_PACKET
#define it_unipr_netsec_rawsocket_Socket_SOCK_PACKET 10L
/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    startup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_it_unipr_netsec_rawsocket_Socket_startup
  (JNIEnv *, jclass);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    cleanup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_it_unipr_netsec_rawsocket_Socket_cleanup
  (JNIEnv *, jclass);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    getPFINET6
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_getPFINET6
  (JNIEnv *, jclass);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    setdebug
 * Signature: (Z)V
 */
JNIEXPORT void JNICALL Java_it_unipr_netsec_rawsocket_Socket_setdebug
  (JNIEnv *, jclass, jboolean);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    socket
 * Signature: (III)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_socket
  (JNIEnv *, jobject, jint, jint, jint);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    close
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_it_unipr_netsec_rawsocket_Socket_close
  (JNIEnv *, jobject, jint);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    bind
 * Signature: (II[BI)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_bind
  (JNIEnv *, jobject, jint, jint, jbyteArray, jint);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    sendto
 * Signature: (I[BIIIILjava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_sendto
  (JNIEnv *, jobject, jint, jbyteArray, jint, jint, jint, jint, jstring, jint);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    recv
 * Signature: (I[BII)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_recv
  (JNIEnv *, jobject, jint, jbyteArray, jint, jint);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    recvfrom
 * Signature: (I[BII[B[B)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_recvfrom
  (JNIEnv *, jobject, jint, jbyteArray, jint, jint, jbyteArray, jbyteArray);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    setsockopt
 * Signature: (III[BII)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_setsockopt
  (JNIEnv *, jobject, jint, jint, jint, jbyteArray, jint, jint);

/*
 * Class:     it_unipr_netsec_rawsocket_Socket
 * Method:    getsockopt
 * Signature: (III[BI)I
 */
JNIEXPORT jint JNICALL Java_it_unipr_netsec_rawsocket_Socket_getsockopt
  (JNIEnv *, jobject, jint, jint, jint, jbyteArray, jint);

#ifdef __cplusplus
}
#endif
#endif
