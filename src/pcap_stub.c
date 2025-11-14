/* Minimal pcap stub implementation for local testing only.
 * This file's symbols are enabled only when compiled with -DUSE_STUB.
 */
#ifdef USE_STUB
#include "pcap.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

struct pcap { int dummy; };

int pcap_findalldevs(pcap_if_t **alldevs, char *errbuf) {
    if (!alldevs) return -1;
    pcap_if_t *dev = (pcap_if_t*)malloc(sizeof(pcap_if_t));
    dev->name = (char*)malloc(3);
    strcpy(dev->name, "lo");
    dev->description = (char*)malloc(32);
    strcpy(dev->description, "Loopback Interface (stub)");
    dev->next = NULL;
    *alldevs = dev;
    return 0;
}

void pcap_freealldevs(pcap_if_t *alldevs) {
    while (alldevs) {
        pcap_if_t *next = alldevs->next;
        free(alldevs->name);
        free(alldevs->description);
        free(alldevs);
        alldevs = next;
    }
}

pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf) {
    (void)device; (void)snaplen; (void)promisc; (void)to_ms; (void)errbuf;
    pcap_t *p = (pcap_t*)malloc(sizeof(pcap_t));
    return p;
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
    (void)p; (void)user;
    int sent = 0;
    for (int i = 0; i < 3 && (cnt == 0 || i < cnt); ++i) {
        struct pcap_pkthdr hdr;
        hdr.len = 64 + i;
        hdr.caplen = hdr.len;
        hdr.ts.tv_sec = (long)time(NULL);
        hdr.ts.tv_usec = 0;
        unsigned char data[128] = {0};
        if (callback) callback(NULL, &hdr, data);
        sent++;
    }
    return sent;
}

void pcap_close(pcap_t *p) { free(p); }

/* --- Simple pcap savefile implementation ---
 * This writes a global header followed by packet records in the
 * libpcap file format. It's minimal but sufficient for Wireshark.
 */
struct pcap_dumper { FILE *fp; };

pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname) {
    (void)p;
    pcap_dumper_t *d = (pcap_dumper_t*)malloc(sizeof(pcap_dumper_t));
    d->fp = fopen(fname, "wb");
    if (!d->fp) { free(d); return NULL; }

    /* Write pcap global header (little-endian, microsecond timestamps) */
    uint32_t magic = 0xa1b2c3d4;
    uint16_t major = 2, minor = 4;
    int32_t tz = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 65535;
    uint32_t linktype = 1; /* DLT_EN10MB (Ethernet) - reasonable default */

    fwrite(&magic, 4, 1, d->fp);
    fwrite(&major, 2, 1, d->fp);
    fwrite(&minor, 2, 1, d->fp);
    fwrite(&tz, 4, 1, d->fp);
    fwrite(&sigfigs, 4, 1, d->fp);
    fwrite(&snaplen, 4, 1, d->fp);
    fwrite(&linktype, 4, 1, d->fp);

    fflush(d->fp);
    return d;
}

void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp) {
    pcap_dumper_t *d = (pcap_dumper_t*)user;
    if (!d || !d->fp || !h) return;

    uint32_t ts_sec = (uint32_t)h->ts.tv_sec;
    uint32_t ts_usec = (uint32_t)h->ts.tv_usec;
    uint32_t caplen = (uint32_t)h->caplen;
    uint32_t len = (uint32_t)h->len;

    fwrite(&ts_sec, 4, 1, d->fp);
    fwrite(&ts_usec, 4, 1, d->fp);
    fwrite(&caplen, 4, 1, d->fp);
    fwrite(&len, 4, 1, d->fp);
    if (caplen && sp) fwrite(sp, 1, caplen, d->fp);
    fflush(d->fp);
}

void pcap_dump_close(pcap_dumper_t *p) { if (p) { if (p->fp) fclose(p->fp); free(p); } }

#else /* USE_STUB not defined: don't export the stub symbols */

/* When not building with USE_STUB, leave this file empty so the
 * real libpcap/wpcap symbols will be used at link time.
 */

#endif /* USE_STUB */
