/* pcap.h compatibility shim
 * If USE_STUB is defined, export a minimal stub API sufficient for
 * local testing. Otherwise try to include the system libpcap/wpcap
 * header. This allows building either with the real packet capture
 * SDK or the local stub by toggling the USE_STUB compile flag.
 */

#ifndef SRC_PCAP_COMPAT_H
#define SRC_PCAP_COMPAT_H

#ifdef USE_STUB

/* Minimal stub implementation used for local testing only. */
#include <time.h>
#include <stdlib.h>

typedef unsigned int bpf_u_int32;
typedef unsigned char u_char;

/* Ensure struct timeval is available: on Windows use winsock2, otherwise sys/time.h */
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/time.h>
#endif

struct pcap_pkthdr {
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

typedef struct pcap_if {
    char *name;
    char *description;
    struct pcap_if *next;
} pcap_if_t;

typedef struct pcap pcap_t;

typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

/* Define a reasonable errbuf size similar to libpcap */
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif

/* Return 0 on success, -1 on error. */
int pcap_findalldevs(pcap_if_t **alldevs, char *errbuf);
void pcap_freealldevs(pcap_if_t *alldevs);

pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
void pcap_close(pcap_t *p);

/* Simple pcap dump (savefile) API compatible with libpcap's helpers. */
typedef struct pcap_dumper pcap_dumper_t;
pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);
void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);
void pcap_dump_close(pcap_dumper_t *p);

#else /* not USE_STUB */

/* Prefer the system / SDK header when not using the stub. */
#ifdef _WIN32
/* On Windows, the packet capture API is provided by wpcap/winpcap/Npcap. */
#include <pcap.h>
#else
#include <pcap.h>
#endif

/* Some libpcap distributions supply pcap_dump helpers in the header
 * via pcap_dump_open/pcl_dump/pcl_dump_close; if the system header
 * doesn't declare them, declare fallbacks here so code using them
 * still compiles. We check for PCAP_DUMP_AVAILABLE to avoid redeclaring
 * when the header already supplies them. */
#ifndef PCAP_DUMP_AVAILABLE
typedef struct pcap_dumper pcap_dumper_t;
pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);
void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);
void pcap_dump_close(pcap_dumper_t *p);
#endif

#endif /* USE_STUB */

#endif /* SRC_PCAP_COMPAT_H */
/* Minimal stub of pcap.h for local testing only.
   This file provides just enough types and functions to compile
   and run a simulated capture when libpcap/Npcap isn't installed.
   Do NOT use this in production; remove it when building with the
   real pcap SDK and/or link against -lpcap.
*/

#ifndef SRC_PCAP_STUB_H
#define SRC_PCAP_STUB_H

#include <time.h>
#include <stdlib.h>

typedef unsigned int bpf_u_int32;
typedef unsigned char u_char;

/* Ensure struct timeval is available: on Windows use winsock2, otherwise sys/time.h */
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/time.h>
#endif

struct pcap_pkthdr {
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

typedef struct pcap_if {
    char *name;
    char *description;
    struct pcap_if *next;
} pcap_if_t;

typedef struct pcap pcap_t;

typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

/* Define a reasonable errbuf size similar to libpcap */
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif

/* Return 0 on success, -1 on error. */
int pcap_findalldevs(pcap_if_t **alldevs, char *errbuf);
void pcap_freealldevs(pcap_if_t *alldevs);

pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
void pcap_close(pcap_t *p);

/* Simple pcap dump (savefile) API compatible with libpcap's helpers.
 * These are provided here so the stub can produce a .pcap file that
 * Wireshark and tcpdump can read. When building against the real
 * libpcap/wpcap, the real functions will be used instead.
 */
typedef struct pcap_dumper pcap_dumper_t;

/* Open a savefile for writing. Returns NULL on error. */
pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);

/* Write a packet to the savefile. The 'user' argument is the dumper
 * pointer cast to (u_char *), matching libpcap's pcap_dump signature. */
void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);

/* Close the savefile. */
void pcap_dump_close(pcap_dumper_t *p);

#endif /* SRC_PCAP_STUB_H */
