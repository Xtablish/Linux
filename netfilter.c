#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include "packet_filter.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xtablish");
MODULE_DESCRIPTION("A simple packet filter kernel module using nf_register_queue_handler");

// Packet processing function for IPv4
static int process_ipv4_packet(struct sk_buff *skb, struct nf_queue_entry *entry) {
    printk(KERN_INFO "Processing IPv4 packet\n");
    return NF_ACCEPT; // Accept the packet
}

// Packet processing function for outbound IPv4 packets
static int process_ipv4_out_packet(struct sk_buff *skb, struct nf_queue_entry *entry) {
    printk(KERN_INFO "Processing outbound IPv4 packet\n");
    return NF_ACCEPT; // Accept the packet
}

// Packet processing function for ARP packets
static int process_arp_packet(struct sk_buff *skb, struct nf_queue_entry *entry) {
    printk(KERN_INFO "Processing ARP packet\n");
    return NF_ACCEPT; // Accept the packet
}

// Register the queue handlers
void register_queue_handlers(struct RegisterQueueHandler *handlers) {
    handlers->qh_in.hook = process_ipv4_packet;
    handlers->qh_in.pf = PF_INET;
    handlers->qh_in.hooknum = NF_INET_PRE_ROUTING;
    
    handlers->qh_out.hook = process_ipv4_out_packet;
    handlers->qh_out.pf = PF_INET;
    handlers->qh_out.hooknum = NF_INET_POST_ROUTING;

    handlers->qh_arp.hook = process_arp_packet;
    handlers->qh_arp.pf = PF_ARP;
    handlers->qh_arp.hooknum = NF_ARP_PRE_ROUTING;

    // Register the queue handlers
    if (nf_register_queue_handler(&init_net, &handlers->qh_in) < 0) {
        printk(KERN_ERR "Failed to register IPv4 inbound queue handler\n");
    } else {
        printk(KERN_INFO "IPv4 inbound queue handler registered successfully\n");
    }

    if (nf_register_queue_handler(&init_net, &handlers->qh_out) < 0) {
        printk(KERN_ERR "Failed to register IPv4 outbound queue handler\n");
    } else {
        printk(KERN_INFO "IPv4 outbound queue handler registered successfully\n");
    }

    if (nf_register_queue_handler(&init_net, &handlers->qh_arp) < 0) {
        printk(KERN_ERR "Failed to register ARP queue handler\n");
    } else {
        printk(KERN_INFO "ARP queue handler registered successfully\n");
    }
}

// Unregister the queue handlers
void unregister_queue_handlers(struct RegisterQueueHandler *handlers) {
    nf_unregister_queue_handler(&init_net, &handlers->qh_in);
    nf_unregister_queue_handler(&init_net, &handlers->qh_out);
    nf_unregister_queue_handler(&init_net, &handlers->qh_arp);
}

// Module initialization
static int __init packet_filter_init(void) {
    struct RegisterQueueHandler handlers;
    register_queue_handlers(&handlers);
    printk(KERN_INFO "Packet filter module loaded\n");
    return 0;
}

// Module exit
static void __exit packet_filter_exit(void) {
    struct RegisterQueueHandler handlers;
    unregister_queue_handlers(&handlers);
    printk(KERN_INFO "Packet filter module unloaded\n");
}

module_init(packet_filter_init);
module_exit(packet_filter_exit);
