#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

struct RegisterQueueHandler {
    struct nf_queue_handler qh_in;
    struct nf_queue_handler qh_out;
    struct nf_queue_handler qh_arp;
};

// Function prototypes
void register_queue_handlers(struct RegisterQueueHandler *handlers);
void unregister_queue_handlers(struct RegisterQueueHandler *handlers);

#endif // PACKET_FILTER_H
