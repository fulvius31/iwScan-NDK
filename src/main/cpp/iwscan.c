/*
 * iwscan — a tiny, self-contained nl80211 Wi-Fi scanner (no libnl dependency).
 *
 * Shipped as libiwscan.so (an executable named like a .so so it lands in nativeLibDir, the only
 * place an Android app may exec from). Run as root by IwScanner when the Android Wi-Fi framework
 * is off, so the app can scan without toggling Wi-Fi on.
 *
 *   Usage: libiwscan.so <iface> <scan|dump>
 *     scan : trigger an active scan, wait, then dump results (default)
 *     dump : print the kernel's last cached scan results only
 *
 * Output mimics the subset of `iw scan` text that IwScanResultParser understands, so the existing
 * Kotlin parser is reused unchanged.
 */
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>

#define ALIGN4(len) (((len) + 3) & ~3)
#define A_HDRLEN ((int)ALIGN4(sizeof(struct nlattr)))
#define A_DATA(na) ((void *)((char *)(na) + A_HDRLEN))
#define A_PAYLOAD(na) ((int)(na)->nla_len - A_HDRLEN)
#define A_OK(na, rem) ((rem) >= (int)sizeof(struct nlattr) && (na)->nla_len >= sizeof(struct nlattr) && (int)(na)->nla_len <= (rem))
#define A_NEXT(na, rem) ((rem) -= ALIGN4((na)->nla_len), (struct nlattr *)((char *)(na) + ALIGN4((na)->nla_len)))

static int nl_fd = -1;
static unsigned int seq = 0;

/* Append an attribute to a netlink message buffer; returns new total length. */
static int add_attr(char *buf, int len, int type, const void *data, int dlen) {
    struct nlattr *na = (struct nlattr *)(buf + ALIGN4(len));
    na->nla_type = type;
    na->nla_len = A_HDRLEN + dlen;
    if (dlen > 0) memcpy(A_DATA(na), data, dlen);
    return ALIGN4(len) + ALIGN4(na->nla_len);
}

/* Send a genetlink request. Returns 0 on success. */
static int send_msg(int family, __u8 cmd, __u16 flags, const char *attrs, int attrs_len) {
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gnlh = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);
    nlh->nlmsg_type = family;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = ++seq;
    nlh->nlmsg_pid = 0;
    gnlh->cmd = cmd;
    gnlh->version = 0;
    int len = NLMSG_HDRLEN + ALIGN4(sizeof(struct genlmsghdr));
    if (attrs_len > 0) {
        memcpy(buf + len, attrs, attrs_len);
        len += attrs_len;
    }
    nlh->nlmsg_len = len;
    struct sockaddr_nl dst;
    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    return sendto(nl_fd, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0 ? -1 : 0;
}

/* Resolve the nl80211 generic-netlink family id. Returns id or -1. */
static int resolve_family(void) {
    char attrs[64];
    const char *name = "nl80211";
    int al = add_attr(attrs, 0, CTRL_ATTR_FAMILY_NAME, name, (int)strlen(name) + 1);
    if (send_msg(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, attrs, al) < 0) return -1;

    char rbuf[8192];
    int n = recv(nl_fd, rbuf, sizeof(rbuf), 0);
    if (n < 0) return -1;
    struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf;
    for (; NLMSG_OK(nlh, n); nlh = NLMSG_NEXT(nlh, n)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) return -1;
        struct nlattr *na = (struct nlattr *)((char *)NLMSG_DATA(nlh) + ALIGN4(sizeof(struct genlmsghdr)));
        int rem = NLMSG_PAYLOAD(nlh, 0) - (int)ALIGN4(sizeof(struct genlmsghdr));
        for (; A_OK(na, rem); na = A_NEXT(na, rem)) {
            if (na->nla_type == CTRL_ATTR_FAMILY_ID) return *(__u16 *)A_DATA(na);
        }
    }
    return -1;
}

static void print_ssid(const unsigned char *p, int len) {
    fputs("\tSSID: ", stdout);
    for (int i = 0; i < len; i++) {
        unsigned char c = p[i];
        if (c >= 0x20) putchar(c); /* drop control chars (incl. newlines) to keep one line */
    }
    putchar('\n');
}

/* Parse RSN/WPA AKM suites to flag SAE (WPA3) / OWE. */
static void parse_rsn(const unsigned char *p, int len, int *sae, int *owe) {
    if (len < 8) return;
    int off = 2;                /* version */
    off += 4;                   /* group cipher */
    if (off + 2 > len) return;
    int pc = p[off] | (p[off + 1] << 8);
    off += 2 + pc * 4;          /* pairwise ciphers */
    if (off + 2 > len) return;
    int ac = p[off] | (p[off + 1] << 8);
    off += 2;
    for (int i = 0; i < ac && off + 4 <= len; i++, off += 4) {
        if (p[off] == 0x00 && p[off + 1] == 0x0f && p[off + 2] == 0xac) {
            if (p[off + 3] == 8) *sae = 1;      /* SAE  -> WPA3 */
            if (p[off + 3] == 18) *owe = 1;     /* OWE */
        }
    }
}

/* Parse a WPS vendor IE for setup state and config methods, emit iw-style lines. */
static void parse_wps(const unsigned char *p, int len) {
    fputs("\tWPS:\n", stdout);
    int off = 0;
    int have_state = 0;
    while (off + 4 <= len) {
        int t = (p[off] << 8) | p[off + 1];
        int l = (p[off + 2] << 8) | p[off + 3];
        off += 4;
        if (off + l > len) break;
        if (t == 0x1044 && l >= 1) { /* Wi-Fi Protected Setup State */
            printf("\t\t * Wi-Fi Protected Setup State: %d\n", p[off]);
            have_state = 1;
        } else if (t == 0x1008 && l >= 2) { /* Config methods */
            printf("\t\t * Config methods: 0x%04x\n", (p[off] << 8) | p[off + 1]);
        } else if (t == 0x1057 && l >= 1) { /* AP Setup Locked */
            printf("\t\t * AP setup locked: 0x%02x\n", p[off]);
        }
        off += l;
    }
    if (!have_state) printf("\t\t * Wi-Fi Protected Setup State: 2\n");
}

/* Emit SSID + security lines from one IE blob (WPS handled separately). */
static void emit_meta(const unsigned char *ie, int len, int privacy) {
    int sae = 0, owe = 0, has_rsn = 0, has_wpa = 0;
    int o = 0;
    while (o + 2 <= len) {
        int id = ie[o], l = ie[o + 1];
        if (o + 2 + l > len) break;
        const unsigned char *d = ie + o + 2;
        if (id == 0) {
            print_ssid(d, l);
        } else if (id == 48) {
            has_rsn = 1;
            parse_rsn(d, l, &sae, &owe);
        } else if (id == 221 && l >= 4 &&
                   d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xf2 && d[3] == 0x01) {
            has_wpa = 1; /* WPA1 vendor IE */
        }
        o += 2 + l;
    }
    if (has_rsn) fputs("\tRSN:\n", stdout);
    if (sae) fputs("\t\t * Authentication suites: SAE\n", stdout);
    if (owe) fputs("\t\t * Authentication suites: OWE\n", stdout);
    if (has_wpa) fputs("\tWPA:\n", stdout);
    if (privacy) fputs("\tcapability: Privacy\n", stdout);
}

/*
 * Append the payload of every WPS vendor IE (00:50:F2:04) found in 'ie' to 'out'. WPS info can be
 * split across multiple vendor elements and may differ between probe-response and beacon IEs (the
 * "AP Setup Locked" attribute in particular is often only in the beacon), so callers concatenate
 * both sources before parsing. Returns the new used length.
 */
static int collect_wps(const unsigned char *ie, int len, unsigned char *out, int outcap, int used) {
    int o = 0;
    while (o + 2 <= len) {
        int id = ie[o], l = ie[o + 1];
        if (o + 2 + l > len) break;
        const unsigned char *d = ie + o + 2;
        if (id == 221 && l >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xf2 && d[3] == 0x04) {
            int plen = l - 4;
            if (plen > 0 && used + plen <= outcap) {
                memcpy(out + used, d + 4, plen);
                used += plen;
            }
        }
        o += 2 + l;
    }
    return used;
}

static void parse_bss(struct nlattr *bss) {
    int rem = A_PAYLOAD(bss);
    struct nlattr *na = (struct nlattr *)A_DATA(bss);
    unsigned char bssid[6] = {0};
    int have_bssid = 0;
    unsigned int freq = 0;
    int signal_dbm = -100;
    unsigned int privacy = 0;
    const unsigned char *ie = NULL;
    int ie_len = 0;
    const unsigned char *beacon_ie = NULL;
    int beacon_len = 0;

    for (; A_OK(na, rem); na = A_NEXT(na, rem)) {
        switch (na->nla_type) {
            case NL80211_BSS_BSSID:
                if (A_PAYLOAD(na) >= 6) { memcpy(bssid, A_DATA(na), 6); have_bssid = 1; }
                break;
            case NL80211_BSS_FREQUENCY:
                freq = *(__u32 *)A_DATA(na);
                break;
            case NL80211_BSS_SIGNAL_MBM:
                signal_dbm = (int)(*(__s32 *)A_DATA(na)) / 100; /* mBm -> dBm */
                break;
            case NL80211_BSS_CAPABILITY:
                privacy = (*(__u16 *)A_DATA(na)) & 0x0010; /* Privacy bit */
                break;
            case NL80211_BSS_INFORMATION_ELEMENTS:
                ie = (const unsigned char *)A_DATA(na);
                ie_len = A_PAYLOAD(na);
                break;
            case NL80211_BSS_BEACON_IES:
                beacon_ie = (const unsigned char *)A_DATA(na);
                beacon_len = A_PAYLOAD(na);
                break;
        }
    }
    if (!have_bssid) return;
    printf("BSS %02x:%02x:%02x:%02x:%02x:%02x\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    printf("\tfreq: %u\n", freq);
    printf("\tsignal: %d.00 dBm\n", signal_dbm);
    /* SSID/security from the probe-response IEs (fall back to beacon IEs). */
    const unsigned char *meta = ie ? ie : beacon_ie;
    int meta_len = ie ? ie_len : beacon_len;
    if (meta) emit_meta(meta, meta_len, (int)privacy);

    /* WPS attributes: merge from BOTH probe and beacon IEs so we don't miss "AP Setup Locked". */
    unsigned char wpsbuf[2048];
    int wpslen = 0;
    if (ie) wpslen = collect_wps(ie, ie_len, wpsbuf, (int)sizeof(wpsbuf), wpslen);
    if (beacon_ie) wpslen = collect_wps(beacon_ie, beacon_len, wpsbuf, (int)sizeof(wpsbuf), wpslen);
    if (wpslen > 0) parse_wps(wpsbuf, wpslen);
}

static void dump_results(int family, int ifindex) {
    char attrs[64];
    int al = add_attr(attrs, 0, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex));
    send_msg(family, NL80211_CMD_GET_SCAN, NLM_F_DUMP, attrs, al);

    char rbuf[65536];
    for (;;) {
        int n = recv(nl_fd, rbuf, sizeof(rbuf), 0);
        if (n <= 0) break;
        struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf;
        int done = 0;
        for (; NLMSG_OK(nlh, n); nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_type == NLMSG_DONE) { done = 1; break; }
            if (nlh->nlmsg_type == NLMSG_ERROR) { done = 1; break; }
            struct nlattr *na = (struct nlattr *)((char *)NLMSG_DATA(nlh) + ALIGN4(sizeof(struct genlmsghdr)));
            int rem = (int)nlh->nlmsg_len - NLMSG_HDRLEN - (int)ALIGN4(sizeof(struct genlmsghdr));
            for (; A_OK(na, rem); na = A_NEXT(na, rem)) {
                if (na->nla_type == NL80211_ATTR_BSS) parse_bss(na);
            }
        }
        if (done) break;
    }
}

static void trigger_scan(int family, int ifindex) {
    /* IFINDEX + a single wildcard SSID (active scan). */
    char attrs[128];
    int al = add_attr(attrs, 0, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex));
    /* nested NL80211_ATTR_SCAN_SSIDS with one zero-length SSID (type index 1). */
    struct nlattr *nest = (struct nlattr *)(attrs + ALIGN4(al));
    nest->nla_type = NL80211_ATTR_SCAN_SSIDS;
    struct nlattr *sub = (struct nlattr *)A_DATA(nest);
    sub->nla_type = 1;
    sub->nla_len = A_HDRLEN; /* zero-length payload */
    nest->nla_len = A_HDRLEN + ALIGN4(sub->nla_len);
    al = ALIGN4(al) + ALIGN4(nest->nla_len);
    send_msg(family, NL80211_CMD_TRIGGER_SCAN, 0, attrs, al);
    /* Drain the ack/result; then give the driver time to complete the scan. */
    char rbuf[4096];
    recv(nl_fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
    sleep(4);
}

int main(int argc, char **argv) {
    const char *iface = argc > 1 ? argv[1] : "wlan0";
    const char *mode = argc > 2 ? argv[2] : "scan";

    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "iwscan: no interface %s\n", iface);
        return 1;
    }

    nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (nl_fd < 0) {
        fprintf(stderr, "iwscan: socket: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    if (bind(nl_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        fprintf(stderr, "iwscan: bind: %s\n", strerror(errno));
        return 1;
    }

    int family = resolve_family();
    if (family < 0) {
        fprintf(stderr, "iwscan: nl80211 family not found\n");
        return 1;
    }

    if (strcmp(mode, "scan") == 0) {
        trigger_scan(family, (int)ifindex);
    }
    dump_results(family, (int)ifindex);
    return 0;
}
