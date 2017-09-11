/*
 Copyright (c) 2017 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

#include <gimxprio/include/gprio.h>
#include <gimxusb/include/gusb.h>
#include <gimxpoll/include/gpoll.h>
#include <gimxcommon/include/glist.h>
#include <gimxcommon/include/gerror.h>
#include <gimxtimer/include/gtimer.h>

#ifdef WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include <stddef.h>
#endif

#include "names.h"

#ifndef WIN32
#define REGISTER_FUNCTION gpoll_register_fd
#define REMOVE_FUNCTION gpoll_remove_fd
#else
#define REGISTER_FUNCTION gpoll_register_handle
#define REMOVE_FUNCTION gpoll_remove_handle
#endif

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"

#define guint32 uint32_t
#define guint16 uint16_t
#define gint32 int32_t

typedef struct pcap_hdr_s {
  guint32 magic_number; /* magic number */
  guint16 version_major; /* major version number */
  guint16 version_minor; /* minor version number */
  gint32 thiszone; /* GMT to local correction */
  guint32 sigfigs; /* accuracy of timestamps */
  guint32 snaplen; /* max length of captured packets, in octets */
  guint32 network; /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  guint32 ts_sec; /* timestamp seconds */
  guint32 ts_usec; /* timestamp microseconds */
  guint32 incl_len; /* number of octets of packet saved in file */
  guint32 orig_len; /* actual length of packet */
} pcaprec_hdr_t;

#define DLT_USB_LINUX_MMAPPED 220

#define u64 uint64_t
#define u16 uint16_t
#define s64 int64_t
#define s32 int32_t

#define SETUP_LEN 8

typedef struct usbmon_packet {
	u64 id;			/*  0: URB ID - from submission to callback */
	unsigned char type;	/*  8: Same as text; extensible. */
	unsigned char xfer_type; /*    ISO (0), Intr, Control, Bulk (3) */
	unsigned char epnum;	/*     Endpoint number and transfer direction */
	unsigned char devnum;	/*     Device address */
	u16 busnum;		/* 12: Bus number */
	char flag_setup;	/* 14: Same as text */
	char flag_data;		/* 15: Same as text; Binary zero is OK. */
	s64 ts_sec;		/* 16: gettimeofday */
	s32 ts_usec;		/* 24: gettimeofday */
	int status;		/* 28: */
	unsigned int length;	/* 32: Length of data (submitted or actual) */
	unsigned int len_cap;	/* 36: Delivered length */
	union {			/* 40: */
		unsigned char setup[SETUP_LEN];	/* Only for Control S-type */
		struct iso_rec {		/* Only for ISO */
			int error_count;
			int numdesc;
		} iso;
	} s;
	int interval;		/* 48: Only for Interrupt and ISO */
	int start_frame;	/* 52: For ISO */
	unsigned int xfer_flags; /* 56: copy of URB's transfer_flags */
	unsigned int ndesc;	/* 60: Actual number of ISO descriptors */
} usbmon_packet_t;				/* 64 total length */

#define PACKET_TYPE_SUBMIT 'S'
#define PACKET_TYPE_COMPLETE 'C'

#define XFER_TYPE_ISOCHRONOUS 0
#define XFER_TYPE_INTERRUPT   1
#define XFER_TYPE_CONTROL     2
#define XFER_TYPE_BULK        3

static FILE * file = NULL;
static char * filename = NULL;

static int dry_run = 0;

static volatile int done = 0;

void terminate(int sig) {

  done = 1;
}

int pcapreader_init() {

    file = fopen(filename, "r");

    if (file == NULL) {
        fprintf(stderr, "fopen");
        return -1;
    }
    
    pcap_hdr_t capture_header;
    
    int ret = fread(&capture_header, 1, sizeof(capture_header), file);
    
    if (ret != sizeof(capture_header)) {
        fprintf(stderr, "unable to read pcap header\n");
        return -1;
    }
    
    if (capture_header.magic_number != 0xa1b2c3d4) {
        fprintf(stderr, "unable to read pcap header magic byte\n");
        return -1;
    }
    
    if (capture_header.network != DLT_USB_LINUX_MMAPPED) {
        fprintf(stderr, "invalid network type: %x\n", capture_header.network);
        return -1;
    }
    
    return 0;
}

static void dump(const unsigned char* packet, unsigned char length)
{
  int i;
  for(i = 0; i < length; ++i)
  {
    printf("0x%02x ", packet[i]);
  }
}

struct transfer {
    usbmon_packet_t * s; // submitted request
    usbmon_packet_t * c; // completion result
    GLIST_LINK(struct transfer)
};

static int transfer_close(struct transfer * t) {

    GLIST_REMOVE(transfers, t)

    free(t->s);
    free(t->c);
    free(t);

    return 0;
}

GLIST_INST(struct transfer, transfers, transfer_close)

// the target device
static struct cap_device * device_info = NULL;
static struct gusb_device * usb_device = NULL;
static struct endpoints eps;

static uint8_t cap_to_device_endpoint[16][2] = {};

// first index is the endpoint (0 to 15), second index is the direction (0 = OUT, 1 = IN)
// ep0 is always OUT
static struct transfer * ep_transfers[16][2] = {};

static struct {
    struct transfer * transfer;
    unsigned long long int time;
} last = {
        .transfer = NULL,
        .time = 0, // the time of the transfer, in microseconds
};

// one-shot timer to schedule the next transfer
static struct gtimer * next_timer = NULL;

#ifndef WIN32
static inline unsigned long long int get_time() {

  struct timeval now;
  gettimeofday(&now, NULL);
  return now.tv_sec * 1000000 + now.tv_usec;
}
#else
static inline unsigned long long int get_time() {

  FILETIME ftime;
  GetSystemTimeAsFileTime(&ftime);
  LARGE_INTEGER li = { .HighPart = ftime.dwHighDateTime, .LowPart = ftime.dwLowDateTime };
  return li.QuadPart / 10;
}
#endif

void dump_packet(usbmon_packet_t * rec) {
    
    printf("%lu.%06u %d", rec->ts_sec, rec->ts_usec, rec->devnum);

    switch (rec->type) {
    case PACKET_TYPE_SUBMIT:
        printf(" submit");
        break;
    case PACKET_TYPE_COMPLETE:
        printf(" complete");
        break;
    default:
        printf(" unknown");
        break;
    }
    
    switch (rec->xfer_type) {
    case XFER_TYPE_ISOCHRONOUS:
        printf(" isochronous");
        break;
    case XFER_TYPE_INTERRUPT:
        printf(" interrupt");
        break;
    case XFER_TYPE_CONTROL:
        printf(" control");
        break;
    case XFER_TYPE_BULK:
        printf(" bulk");
        break;
    default:
        printf(" unknown");
        break;
    }
    
    printf(" ep=%d dir=%s", rec->epnum & 0x0f, rec->epnum & 0x80 ? "IN" : "OUT");
    
    if (rec->flag_setup == 0x00) {
        printf(" setup ");
        dump(rec->s.setup, sizeof(rec->s.setup));
    }
    
    if (rec->flag_data == 0x00) {
        printf(" data ");
        dump(((unsigned char *)rec) + sizeof(*rec), rec->length);
    }
    
    /*
     * https://github.com/libusb/libusb/blob/86b162c335b58b5e6e7cf2d7d079f45aa1675e1e/libusb/os/linux_usbfs.c#L2327
     */
    switch (rec->status) {
      case 0:
          break;
      case -EREMOTEIO:
          printf(" short transfer");
          break;
      case -ENOENT:
      case -ECONNRESET:
          printf(" cancelled");
          break;
      case -ENODEV:
      case -ESHUTDOWN:
          printf(" device removed");
          break;
      case -EPIPE:
          printf(" stall");
          break;
      case -EOVERFLOW:
          printf(" overflow");
          break;
      case -ETIME:
      case -EPROTO:
      case -EILSEQ:
      case -ECOMM:
      case -ENOSR:
          printf(" low level error %d", rec->status);
          break;
      case -EINPROGRESS:
          printf(" in progress");
          break;
      default:
          printf("unrecognised urb status %d", rec->status);
          break;
    }
    
    if (rec->flag_data == 0x00 && rec->len_cap < rec->length) {
        fprintf(stderr, "missing data\n");
    }

    printf("\n");
}

int pcapreader_read() {

    pcaprec_hdr_t rec_header;

    int ret = fread(&rec_header, 1, sizeof(rec_header), file);

    if (ret != sizeof(rec_header)) {
        return -1;
    }

    if (rec_header.incl_len < sizeof(usbmon_packet_t)) {
        fprintf(stderr, "packet is too small (%u bytes)\n", rec_header.incl_len);
        return -1;
    }

    usbmon_packet_t * rec = calloc(1, rec_header.incl_len);
    if (rec == NULL) {
        PRINT_ERROR_ALLOC_FAILED("calloc")
        return -1;
    }

    ret = fread(rec, 1, rec_header.incl_len, file);
    if (ret != (int) rec_header.incl_len) {
        fprintf(stderr, "read did not provide the expected size (%d vs %u bytes)\n", ret, rec_header.incl_len);
        return -1;
    }

    if (rec->type == PACKET_TYPE_SUBMIT) {

        struct transfer * t = calloc(1, sizeof(*t));
        if (t == NULL) {
            PRINT_ERROR_ALLOC_FAILED("calloc")
            free(rec);
            return -1;
        }

        t->s = rec;

        GLIST_ADD(transfers, t)

    } else if (rec->type == PACKET_TYPE_COMPLETE) {

        struct transfer * it;
        for (it = (GLIST_END(transfers))->prev; it != GLIST_BEGIN(transfers)->prev; it = it->prev) {
            if (it->c == NULL && it->s->id == rec->id) {
                it->c = rec;
                break;
            }
        }
        if (it == GLIST_BEGIN(transfers)->prev) {
            printf("transfer has no submission\n");
        }
    }

    return 0;
}

static void usage(char * cmd, int status) {

    fprintf(stderr, "Usage: %s [-i filename]\n", cmd);
    exit(status);
}

/*
 * Reads command-line arguments.
 */
static void read_args(int argc, char* argv[]) {

    int c;

    struct option long_options[] =
    {
        /* These options set a flag. */
        {"dry-run",        no_argument, &dry_run,  1},
        /* These options don't set a flag. We distinguish them by their indices. */
        {"input-file",     required_argument, 0, 'i'},
        {"help",           no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while (1)
    {
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "i:h", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* If this option set a flag, do nothing else now. */
            if (long_options[option_index].flag != 0)
                break;
            break;

        case 'i':
            filename = optarg;
            break;

        case 'h':
            usage(argv[0], 0);
            break;

        default:
            fprintf(stderr, "unrecognized option: %c\n", c);
            usage(argv[0], EXIT_FAILURE);
            break;
        }
    }

    if (filename == NULL) {
        usage(argv[0], EXIT_FAILURE);
    }
}

static char * select_device(uint16_t vid, uint16_t pid) {

    char * path = NULL;

    struct gusb_device_info * usb_devs = gusb_enumerate(vid, pid);
    if (usb_devs == NULL) {
        PRINT_ERROR_OTHER("None of the connected USB devices match!")
        return NULL;
    }
    printf("Available USB devices:\n");
    unsigned int index = 0;
    char vendor[128], product[128];
    struct gusb_device_info * current;
    for (current = usb_devs; current != NULL; current = current->next) {
        get_vendor_string(vendor, sizeof(vendor), current->vendor_id);
        get_product_string(product, sizeof(product), current->vendor_id, current->product_id);
        printf("%2d", index++);
        printf(" VID 0x%04x (%s)", current->vendor_id, strlen(vendor) ? vendor : "unknown vendor");
        printf(" PID 0x%04x (%s)", current->product_id, strlen(product) ? product : "unknown product");
        printf(" PATH %s\n", current->path);
    }

    printf("Select the USB device number: ");
    unsigned int choice = UINT_MAX;
    if (scanf("%d", &choice) == 1 && choice < index) {
        for (current = usb_devs; current != NULL && choice != 0; current = current->next) {
            --choice;
        }
        path = strdup(current->path);
        if (path == NULL) {
            PRINT_ERROR_OTHER("can't duplicate path.");
        }
    } else {
        PRINT_ERROR_OTHER("Invalid choice.");
    }

    gusb_free_enumeration(usb_devs);

    return path;
}

struct endpoints {
    uint8_t nb;
    struct usb_endpoint_descriptor * descriptors[2 * USB_ENDPOINT_NUMBER_MASK];
};

struct cap_device {
    uint16_t vid;
    uint16_t pid;
    u16 busnum;
    unsigned char devnum;
    struct usb_config_descriptor * config;
    struct endpoints eps;
    GLIST_LINK(struct cap_device)
};

static int close_file_device_info(struct cap_device * device);

GLIST_INST(struct cap_device, cap_devices, close_file_device_info)

static int close_file_device_info(struct cap_device * device) {

    GLIST_REMOVE(cap_devices, device)

    free(device);

    return 0;
}

static int get_devices() {

    struct transfer * it;
    for (it = GLIST_BEGIN(transfers); it != GLIST_END(transfers); it = it->next) {
        if (it->s->xfer_type == XFER_TYPE_CONTROL && it->s->flag_setup == 0x00) {
            struct usb_ctrlrequest * req = (struct usb_ctrlrequest *) it->s->s.setup;
            if (req->bRequestType == USB_DIR_IN
             && req->bRequest == USB_REQ_GET_DESCRIPTOR
             && req->wValue == (USB_DT_DEVICE << 8)) {
                if (it->c == NULL || it->c->status != 0) {
                    continue;
                }
                if (it->c->flag_data != 0x00 || it->c->length < sizeof(struct usb_device_descriptor)) {
                    continue;
                }
                struct usb_device_descriptor * desc = (struct usb_device_descriptor *) (((unsigned char *)it->c) + sizeof(*(it->c)));
                struct cap_device * it2;
                for (it2 = GLIST_BEGIN(cap_devices); it2 != GLIST_END(cap_devices); it2 = it2->next) {
                    if (it2->vid == desc->idVendor && it2->pid == desc->idProduct
                     && it2->busnum == it->c->busnum && it2->devnum == it->c->devnum) {
                        break;
                    }
                }
                if (it2 != GLIST_END(cap_devices)) {
                    continue;
                }
                struct cap_device * device = calloc(1, sizeof(*device));
                if (device == NULL) {
                    PRINT_ERROR_ALLOC_FAILED("calloc")
                    return -1;
                }
                device->vid = desc->idVendor;
                device->pid = desc->idProduct;
                device->busnum = it->c->busnum;
                device->devnum = it->c->devnum;
                GLIST_ADD(cap_devices, device);
            }
        }
    }

    if (GLIST_IS_EMPTY(cap_devices)) {
        PRINT_ERROR_OTHER("no device found in the capture file")
        return -1;
    }

    return 0;
}

static int get_endpoint(struct usb_endpoint_descriptor * endpoint, struct endpoints * eps) {

    if (eps->nb == sizeof(eps->descriptors) / sizeof(*eps->descriptors)) {
        PRINT_ERROR_OTHER("no more room to store endpoint layout")
        return -1;
    }

    eps->descriptors[eps->nb] = endpoint;
    if (dry_run) {
        printf("  address 0x%02x, attributes 0x%02x max packet size %d, interval %u\n", endpoint->bEndpointAddress, endpoint->bmAttributes, endpoint->wMaxPacketSize, endpoint->bInterval);
    }
    ++eps->nb;

    return 0;
}

static int get_endpoints(struct usb_config_descriptor * config, struct endpoints * eps) {

    void * ptr = config;
    ptr += config->bLength;

    if (dry_run) {
        printf("endpoints:\n");
    }

    while (ptr < (void *) config + config->wTotalLength) {

        struct usb_descriptor_header * header = ptr;

        switch (header->bDescriptorType) {
        case USB_DT_ENDPOINT:
            if (get_endpoint(ptr, eps) < 0) {
                return -1;
            }
            break;
        default:
            break;
        }

        ptr += header->bLength;
    }

    return 0;
}

static int get_configuration() {

    struct transfer * it;
    for (it = GLIST_BEGIN(transfers); it != GLIST_END(transfers); it = it->next) {
        if (it->s->busnum != device_info->busnum || it->s->devnum != device_info->devnum) {
            continue;
        }
        if (it->s->xfer_type == XFER_TYPE_CONTROL && it->s->flag_setup == 0x00) {
            struct usb_ctrlrequest * req = (struct usb_ctrlrequest *) it->s->s.setup;
            if (req->bRequestType == USB_DIR_IN
             && req->bRequest == USB_REQ_GET_DESCRIPTOR
             && req->wValue == (USB_DT_CONFIG << 8)) {
                if (it->c == NULL || it->c->status != 0) {
                    continue;
                }
                if (it->c->flag_data != 0x00 || it->c->length < sizeof(struct usb_config_descriptor)) {
                    continue;
                }
                struct usb_config_descriptor * desc = (struct usb_config_descriptor *) (((unsigned char *)it->c) + sizeof(*(it->c)));
                if (desc->wTotalLength != it->c->length) {
                    continue;
                }
                device_info->config = desc;
                return 0;
            }
        }
    }

    return -1;
}

static struct cap_device * select_device_pcap() {

    printf("USB devices found in the capture file:\n");
    unsigned int index = 0;
    char vendor[128];
    char product[128];
    struct cap_device * it;
    for (it = GLIST_BEGIN(cap_devices); it != GLIST_END(cap_devices); it = it->next) {
        get_vendor_string(vendor, sizeof(vendor), it->vid);
        get_product_string(product, sizeof(product), it->vid, it->pid);
        printf("%2d", index++);
        printf(" VID 0x%04x (%s)", it->vid, strlen(vendor) ? vendor : "unknown vendor");
        printf(" PID 0x%04x (%s)", it->pid, strlen(product) ? product : "unknown product");
        printf(" BUS %d DEVICE %d\n", it->busnum, it->devnum);
    }

    printf("Select the USB device number: ");
    unsigned int choice = UINT_MAX;
    if (scanf("%d", &choice) == 1 && choice < index) {
        for (it = GLIST_BEGIN(cap_devices); it != GLIST_END(cap_devices) && choice != 0; it = it->next) {
            --choice;
        }
        return it;
    } else {
        PRINT_ERROR_OTHER("Invalid choice.");
    }

    return NULL;
}

struct transfer * get_next_transfer(struct transfer * t) {

    struct transfer * it;
    for (it = t->next; it != GLIST_END(transfers); it = it->next) {
        if (it->s->busnum == device_info->busnum && it->s->devnum == device_info->devnum) {
            if (it->s->status == -EINPROGRESS && it->c != NULL) {
                return it;
            }
        }
    }
    return NULL;
}

static int timer_read(void * user __attribute__((unused))) {

    if (done) {
        return 1; // make gpoll return
    }

    return 0;
}

static int timer_close(void * user __attribute__((unused))) {

    done = 1;

    return 1;
}

static int submit_transfer(void * user);

static int schedule_transfer(struct transfer * t, unsigned int usec) {

    GTIMER_CALLBACKS timer_cb = {
            .fp_read = submit_transfer,
            .fp_close = timer_close,
            .fp_register = REGISTER_FUNCTION,
            .fp_remove = REMOVE_FUNCTION,
    };
    next_timer = gtimer_start(t, usec, &timer_cb);
    if (next_timer == NULL) {
        return 1;
    }
    return 0;
}

static int submit_transfer(void * user) {

    if (done) {
        return 1;
    }

    struct transfer * t = (struct transfer *) user;

    if (t == NULL) {
        done = 1;
        return 1;
    }

    if (next_timer != NULL) {
        gtimer_close(next_timer);
        next_timer = NULL;
    }

    last.time = get_time();

    if (dry_run == 0) {

        uint8_t ep_num = t->s->epnum;

        ep_num =  cap_to_device_endpoint[ep_num & USB_ENDPOINT_NUMBER_MASK][ep_num >> 7];

        if (ep_transfers[ep_num & USB_ENDPOINT_NUMBER_MASK][ep_num >> 7] != NULL) {
            printf("a transfer is pending for endpoint 0x%02x, retry in 1ms\n", ep_num);
            if (schedule_transfer(t, 1000) < 0) {
                done = 1;
                return 1;
            }
            return 0;
        }

        int ret = -1;

        switch (t->s->xfer_type) {
        case XFER_TYPE_INTERRUPT:
            if ((ep_num & USB_ENDPOINT_DIR_MASK) == USB_DIR_IN) {
                ret = gusb_poll(usb_device, ep_num);
                if (ret == -1) {
                    PRINT_ERROR_OTHER("gusb_poll failed")
                }
            } else if (t->s->flag_data) {
                ret = gusb_write(usb_device, ep_num, ((unsigned char *)t->s) + sizeof(*t->s), t->s->length);
                if (ret == -1) {
                    PRINT_ERROR_OTHER("gusb_write failed")
                }
            }
            break;
        case XFER_TYPE_CONTROL:
        {
            unsigned char buf[sizeof(t->s->s.setup) + t->s->length];
            memcpy(buf, t->s->s.setup, sizeof(t->s->s.setup));
            memcpy(buf + sizeof(t->s->s.setup), ((unsigned char *)t->s) + sizeof(*t->s), t->s->length);

            struct usb_ctrlrequest * setup = (struct usb_ctrlrequest *) buf;
              if ((setup->bRequestType & USB_RECIP_MASK) == USB_RECIP_ENDPOINT) {
                if (setup->wIndex != 0) {
                  setup->wIndex = cap_to_device_endpoint[setup->wIndex & USB_ENDPOINT_NUMBER_MASK][setup->wIndex >> 7];
                }
            }

            ret = gusb_write(usb_device, 0, buf, sizeof(t->s->s.setup) + t->s->length);
            if (ret == -1) {
                PRINT_ERROR_OTHER("gusb_write failed")
            }
            break;
        }
        case XFER_TYPE_BULK:
        case XFER_TYPE_ISOCHRONOUS:
            PRINT_ERROR_OTHER("bulk and isochronous endpoints are not supported")
            break;
        default:
            break;
        }

        if (ret == 0) {
            ep_transfers[ep_num & USB_ENDPOINT_NUMBER_MASK][ep_num >> 7] = t;
        }

    } else {

        dump_packet(t->s);
    }

    struct transfer * next = get_next_transfer(t);
    if (next != NULL) {
        unsigned long long int delta = next->s->ts_sec * 1000000 + next->s->ts_usec - (t->s->ts_sec * 1000000 + t->s->ts_usec);
        unsigned long long int target = last.time + delta;
        unsigned long long int now = get_time();
        unsigned int usec = 0;
        if (target > now) {
            usec = target - now;
        }
        if (schedule_transfer(next, usec) < 0) {
            done = 1;
            return 1;
        }
    } else {
        done = 1;
        return 1;
    }

    return 0;
}

static void compare_status(struct transfer * t, int status) {

    switch(status) {
    case E_TRANSFER_TIMED_OUT:
        // not supposed to happen as transfers are asynchronous
        break;
    case E_TRANSFER_STALL:
        if (t->c->status != -EPIPE) {
            printf(KRED"transfer stall, expected transfer status: %d\n"KNRM, t->c->status);
        }
        break;
    case E_TRANSFER_ERROR:
        if (t->c->status == 0) {
            printf(KRED"transfer error, expected transfer success\n"KNRM);
        } else if (t->c->status == -EPIPE) {
            printf(KRED"transfer error, expected transfer stall\n"KNRM);
        }
        break;
    default:
        if (t->c->status == -EPIPE) {
            printf(KRED"transfer success, expected transfer stall\n"KNRM);
        } else if (t->c->status != 0) {
            printf(KRED"transfer success, expected transfer error\n"KNRM);
        }
        break;
    }
}

static void compare_data(unsigned int llength, unsigned char * left, unsigned int rlength, unsigned char * right) {

    unsigned int max_length = llength > rlength ? llength : rlength;

    unsigned int i = 0;
    while (i < max_length) {
        unsigned int j;
        for (j = i; j < i + 8; ++j) {
            if (j < llength) {
                int red = 0;
                if (j >= rlength || left[j] != right[j]) {
                    red = 1;
                }
                if (red) {
                    printf(KRED);
                }
                printf("0x%02x ", left[j]);
                if (red) {
                    printf(KNRM);
                }
            } else {
                printf("     ");
            }
        }
        printf("| ");
        for (j = i; j < i + 8; ++j) {
            if (j < rlength) {
                int red = 0;
                if (j >= llength || left[j] != right[j]) {
                    red = 1;
                }
                if (red) {
                    printf(KRED);
                }
                printf("0x%02x ", right[j]);
                if (red) {
                    printf(KNRM);
                }
            } else {
                printf("     ");
            }
        }
        printf("\n");
        i += 8;
    }
}

static int usb_read(void * user __attribute__((unused)), unsigned char endpoint, const void * buf, int status) {

    struct transfer * t = ep_transfers[endpoint & USB_ENDPOINT_NUMBER_MASK][endpoint >> 7];

    compare_status(t, status);

    if (status >= 0 && t->c->status == 0) {

        if (status == 0) {
            if (t->c->flag_data == 0) {
                printf(KRED"expected data\n"KNRM);
            }
        } else {
            if (t->c->flag_data != 0) {
                printf(KRED"unexpected data\n"KNRM);
            } else {
                if (status != t->c->length) {
                    printf(KRED"expected %u bytes, got %d\n"KNRM, t->c->length, status);
                }
                compare_data(t->c->length, ((unsigned char *)t->c) + sizeof(*t->c), status, (unsigned char *)buf);
            }
        }
    }

    ep_transfers[endpoint & USB_ENDPOINT_NUMBER_MASK][endpoint >> 7] = NULL;

    return 0;
}

static int usb_write(void * user __attribute__((unused)), unsigned char endpoint, int status) {

    struct transfer * t = ep_transfers[endpoint & USB_ENDPOINT_NUMBER_MASK][endpoint >> 7];

    compare_status(t, status);

    ep_transfers[endpoint & USB_ENDPOINT_NUMBER_MASK][endpoint >> 7] = NULL;

    return 0;
}

static int usb_close(void * user __attribute__((unused))) {

    done = 1;

    return 1;
}

int main(int argc, char * argv[]) {

    (void) signal(SIGINT, terminate);

    read_args(argc, argv);

    int ret = pcapreader_init();

    if (ret == -1) {
        fclose(file);
        return -1;
    }

    while (pcapreader_read() != -1) ;

    fclose(file);

    ret = get_devices();
    if (ret < 0) {
        return -1;
    }

    device_info = select_device_pcap();
    if (device_info == NULL) {
        return -1;
    }

    ret = get_configuration();
    if (ret == 0) {
        get_endpoints(device_info->config, &device_info->eps);
    } else {
        printf("No device configuration found in the capture file.\n");
        printf("Assuming endpoint layout matches.\n");
    }

    GTIMER_CALLBACKS timer_cb = {
            .fp_read = timer_read,
            .fp_close = timer_close,
            .fp_register = REGISTER_FUNCTION,
            .fp_remove = REMOVE_FUNCTION,
    };
    struct gtimer * timer = gtimer_start(NULL, 100000, &timer_cb);
    if (timer == NULL) {
        return -1;
    }

    if (dry_run == 0) {

        gusb_init();

        char * path = select_device(device_info->vid, device_info->pid);
        if (path == NULL) {
            gusb_exit();
            return -1;
        }

        usb_device = gusb_open_path(path);

        free(path);

        if (usb_device == NULL) {
            gusb_exit();
            return -1;
        }

        const s_usb_descriptors * descriptors = gusb_get_usb_descriptors(usb_device);
        get_endpoints(descriptors->configurations[0].descriptor, &eps);

        if (device_info->eps.nb != eps.nb) {
            printf("capture and target devices do not have the same number of endpoints!\n");
            gusb_close(usb_device);
            gusb_exit();
            return -1;
        }

        int error = 0;
        unsigned int i;
        for (i = 0; i < device_info->eps.nb && error == 0; ++i) {
            if ((eps.descriptors[i]->bEndpointAddress & USB_ENDPOINT_DIR_MASK) != (device_info->eps.descriptors[i]->bEndpointAddress & USB_ENDPOINT_DIR_MASK)) {
                printf("endpoints %u does not have the same direction!\n", i);
                error = 1;
            }
            if (eps.descriptors[i]->bmAttributes != device_info->eps.descriptors[i]->bmAttributes) {
                printf("endpoints %u does not have the same attributes!\n", i);
                error = 1;
            }
            if (eps.descriptors[i]->bInterval != device_info->eps.descriptors[i]->bInterval) {
                printf("endpoints %u does not have the same interval!\n", i);
                error = 1;
            }
            if (eps.descriptors[i]->wMaxPacketSize != device_info->eps.descriptors[i]->wMaxPacketSize) {
                printf("endpoints %u does not have the same max packet size!\n", i);
                error = 1;
            }
        }

        if (error) {
            gusb_close(usb_device);
            gusb_exit();
            return -1;
        }

        printf("endpoints:\n");
        for (i = 0; i < device_info->eps.nb; ++i) {
            cap_to_device_endpoint[device_info->eps.descriptors[i]->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK][device_info->eps.descriptors[i]->bEndpointAddress >> 7] = eps.descriptors[i]->bEndpointAddress;
            printf(" 0X%02x -> 0X%02x\n", device_info->eps.descriptors[i]->bEndpointAddress, eps.descriptors[i]->bEndpointAddress);
        }

        GUSB_CALLBACKS usb_cb = {
                .fp_read = usb_read,
                .fp_write = usb_write,
                .fp_close = usb_close,
                .fp_register = REGISTER_FUNCTION,
                .fp_remove = REMOVE_FUNCTION,
        };
        gusb_register(usb_device, NULL, &usb_cb);

    }

    struct transfer * next = get_next_transfer(&GLIST_HEAD(transfers));

    submit_transfer(next);

    gpoll();

    if (dry_run == 0) {

        gusb_close(usb_device);

        gusb_exit();
    }

    return 0;
}
