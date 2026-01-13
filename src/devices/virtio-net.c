/*
 * rv32emu is freely redistributable under the MIT License. See the file
 * "LICENSE" for information on usage and redistribution of this file.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#endif

#include "virtio.h"

#define VNET_FEATURES_0 (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS)
#define VNET_FEATURES_1 1 /* VIRTIO_F_VERSION_1 */

#define VNET_QUEUE_NUM_MAX 1024
#define VNET_RX_QUEUE_IDX 0
#define VNET_TX_QUEUE_IDX 1
#define VNET_QUEUE (vnet->queues[vnet->queue_sel])

#define VNET_MAX_PACKET 1518

PACKED(struct virtio_net_hdr {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
    uint16_t num_buffers;
});

static void virtio_net_set_fail(virtio_net_state_t *vnet)
{
    vnet->status |= VIRTIO_STATUS_DEVICE_NEEDS_RESET;
    if (vnet->status & VIRTIO_STATUS_DRIVER_OK)
        vnet->interrupt_status |= VIRTIO_INT_CONF_CHANGE;
}

static inline uint32_t vnet_preprocess(virtio_net_state_t *vnet,
                                      uint32_t addr)
{
    /* When MEM_SIZE is 4GB, all 32-bit addresses are in bounds by definition.
     * Use compile-time check to avoid GCC -Wtype-limits warning.
     */
#if MEM_SIZE < 0x100000000ULL
    if ((addr >= MEM_SIZE) || (addr & 0b11)) {
#else
    if (addr & 0b11) {
#endif
        virtio_net_set_fail(vnet);
        return 0;
    }

    return addr >> 2;
}

static void virtio_net_update_status(virtio_net_state_t *vnet, uint32_t status)
{
    vnet->status |= status;
    if (status)
        return;

    /* Reset */
    uint32_t device_features = vnet->device_features;
    uint32_t *ram = vnet->ram;
    int tap_fd = vnet->tap_fd;
    struct virtio_net_config config = vnet->config;
    memset(vnet, 0, sizeof(*vnet));
    vnet->device_features = device_features;
    vnet->ram = ram;
    vnet->tap_fd = tap_fd;
    vnet->config = config;
}

static const struct virtq_desc *vnet_get_desc(virtio_net_state_t *vnet,
                                              const virtio_net_queue_t *queue,
                                              uint16_t desc_idx)
{
    return (const struct virtq_desc *) &vnet->ram[queue->queue_desc +
                                                  desc_idx * 4];
}

static uint16_t vnet_avail_ring_idx(virtio_net_state_t *vnet,
                                    const virtio_net_queue_t *queue,
                                    uint16_t avail_idx)
{
    return vnet->ram[queue->queue_avail + 1 + avail_idx / 2] >>
           (16 * (avail_idx % 2));
}

static void vnet_write_used(virtio_net_state_t *vnet,
                            virtio_net_queue_t *queue,
                            uint16_t buffer_idx,
                            uint32_t len)
{
    uint32_t used = vnet->ram[queue->queue_used] >> 16;
    uint32_t vq_used_addr =
        queue->queue_used + 1 + (used % queue->queue_num) * 2;
    vnet->ram[vq_used_addr] = buffer_idx;
    vnet->ram[vq_used_addr + 1] = len;
    used++;

    vnet->ram[queue->queue_used] &= MASK(16);
    vnet->ram[queue->queue_used] |= ((uint32_t) used) << 16;

    if (!(vnet->ram[queue->queue_avail] & 1))
        vnet->interrupt_status |= VIRTIO_INT_USED_RING;
}

static bool vnet_copy_from_descs(virtio_net_state_t *vnet,
                                 const virtio_net_queue_t *queue,
                                 uint16_t desc_idx,
                                 uint8_t *dst,
                                 uint32_t len)
{
    uint32_t copied = 0;
    uint16_t current = desc_idx;

    while (copied < len) {
        const struct virtq_desc *desc = vnet_get_desc(vnet, queue, current);
        if (desc->flags & VIRTIO_DESC_F_WRITE)
            return false;

        uint32_t to_copy = desc->len;
        if (to_copy > len - copied)
            to_copy = len - copied;

        const uint8_t *src =
            (const uint8_t *) ((uintptr_t) vnet->ram + desc->addr);
        memcpy(dst + copied, src, to_copy);
        copied += to_copy;

        if (!(desc->flags & VIRTIO_DESC_F_NEXT))
            break;
        current = desc->next;
    }

    return copied == len;
}

static bool vnet_copy_to_descs(virtio_net_state_t *vnet,
                               const virtio_net_queue_t *queue,
                               uint16_t desc_idx,
                               const uint8_t *src,
                               uint32_t len)
{
    uint32_t written = 0;
    uint16_t current = desc_idx;

    while (written < len) {
        const struct virtq_desc *desc = vnet_get_desc(vnet, queue, current);
        if (!(desc->flags & VIRTIO_DESC_F_WRITE))
            return false;

        uint32_t to_copy = desc->len;
        if (to_copy > len - written)
            to_copy = len - written;

        uint8_t *dst = (uint8_t *) ((uintptr_t) vnet->ram + desc->addr);
        memcpy(dst, src + written, to_copy);
        written += to_copy;

        if (!(desc->flags & VIRTIO_DESC_F_NEXT))
            break;
        current = desc->next;
    }

    return written == len;
}

static uint32_t vnet_total_desc_len(virtio_net_state_t *vnet,
                                    const virtio_net_queue_t *queue,
                                    uint16_t desc_idx)
{
    uint32_t total = 0;
    uint16_t current = desc_idx;

    while (true) {
        const struct virtq_desc *desc = vnet_get_desc(vnet, queue, current);
        total += desc->len;
        if (!(desc->flags & VIRTIO_DESC_F_NEXT))
            break;
        current = desc->next;
    }

    return total;
}

static void virtio_net_handle_tx(virtio_net_state_t *vnet)
{
    virtio_net_queue_t *queue = &vnet->queues[VNET_TX_QUEUE_IDX];
    uint32_t *ram = vnet->ram;

    uint16_t new_avail = ram[queue->queue_avail] >> 16;
    if (new_avail - queue->last_avail > (uint16_t) queue->queue_num)
        return virtio_net_set_fail(vnet);

    while (queue->last_avail != new_avail) {
        uint16_t queue_idx = queue->last_avail % queue->queue_num;
        uint16_t buffer_idx =
            vnet_avail_ring_idx(vnet, queue, queue_idx);
        uint32_t total_len = vnet_total_desc_len(vnet, queue, buffer_idx);

        if (total_len < sizeof(struct virtio_net_hdr)) {
            vnet_write_used(vnet, queue, buffer_idx, 0);
            queue->last_avail++;
            continue;
        }

        uint8_t *buf = malloc(total_len);
        if (!buf)
            return virtio_net_set_fail(vnet);

        if (!vnet_copy_from_descs(vnet, queue, buffer_idx, buf, total_len)) {
            free(buf);
            return virtio_net_set_fail(vnet);
        }

        uint32_t payload_len = total_len - sizeof(struct virtio_net_hdr);
        if (vnet->tap_fd >= 0 && payload_len) {
            ssize_t written = write(vnet->tap_fd,
                                    buf + sizeof(struct virtio_net_hdr),
                                    payload_len);
            if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                rv_log_error("virtio-net write failed: %s", strerror(errno));
        }

        free(buf);
        vnet_write_used(vnet, queue, buffer_idx, total_len);
        queue->last_avail++;
    }
}

static void virtio_net_handle_rx(virtio_net_state_t *vnet)
{
    virtio_net_queue_t *queue = &vnet->queues[VNET_RX_QUEUE_IDX];
    uint32_t *ram = vnet->ram;

    if (vnet->tap_fd < 0)
        return;

    uint16_t new_avail = ram[queue->queue_avail] >> 16;
    if (new_avail - queue->last_avail > (uint16_t) queue->queue_num)
        return virtio_net_set_fail(vnet);

    while (queue->last_avail != new_avail) {
        uint16_t queue_idx = queue->last_avail % queue->queue_num;
        uint16_t buffer_idx =
            vnet_avail_ring_idx(vnet, queue, queue_idx);
        uint32_t total_len = vnet_total_desc_len(vnet, queue, buffer_idx);
        if (total_len < sizeof(struct virtio_net_hdr)) {
            vnet_write_used(vnet, queue, buffer_idx, 0);
            queue->last_avail++;
            continue;
        }

        uint8_t packet[VNET_MAX_PACKET];
        ssize_t read_len = read(vnet->tap_fd, packet, sizeof(packet));
        if (read_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            rv_log_error("virtio-net read failed: %s", strerror(errno));
            return virtio_net_set_fail(vnet);
        }

        uint32_t payload_len = (uint32_t) read_len;
        uint32_t frame_len = payload_len + sizeof(struct virtio_net_hdr);
        if (frame_len > total_len)
            frame_len = total_len;

        uint8_t *buf = calloc(1, frame_len);
        if (!buf)
            return virtio_net_set_fail(vnet);

        if (payload_len > frame_len - sizeof(struct virtio_net_hdr))
            payload_len = frame_len - sizeof(struct virtio_net_hdr);
        memcpy(buf + sizeof(struct virtio_net_hdr), packet, payload_len);

        if (!vnet_copy_to_descs(vnet, queue, buffer_idx, buf, frame_len)) {
            free(buf);
            return virtio_net_set_fail(vnet);
        }

        free(buf);
        vnet_write_used(vnet, queue, buffer_idx, frame_len);
        queue->last_avail++;
    }
}

static void virtio_queue_notify_handler(virtio_net_state_t *vnet, int index)
{
    virtio_net_queue_t *queue = &vnet->queues[index];
    if (vnet->status & VIRTIO_STATUS_DEVICE_NEEDS_RESET)
        return;

    if (!((vnet->status & VIRTIO_STATUS_DRIVER_OK) && queue->ready))
        return virtio_net_set_fail(vnet);

    if (index == VNET_TX_QUEUE_IDX)
        virtio_net_handle_tx(vnet);
    else if (index == VNET_RX_QUEUE_IDX)
        virtio_net_handle_rx(vnet);
}

uint32_t virtio_net_read(virtio_net_state_t *vnet, uint32_t addr)
{
    addr = addr >> 2;
#define _(reg) VIRTIO_##reg
    switch (addr) {
    case _(MagicValue):
        return VIRTIO_MAGIC_NUMBER;
    case _(Version):
        return VIRTIO_VERSION;
    case _(DeviceID):
        return VIRTIO_NET_DEV_ID;
    case _(VendorID):
        return VIRTIO_VENDOR_ID;
    case _(DeviceFeatures):
        return vnet->device_features_sel == 0
                   ? VNET_FEATURES_0 | vnet->device_features
                   : (vnet->device_features_sel == 1 ? VNET_FEATURES_1 : 0);
    case _(QueueNumMax):
        return VNET_QUEUE_NUM_MAX;
    case _(QueueReady):
        return (uint32_t) VNET_QUEUE.ready;
    case _(InterruptStatus):
        return vnet->interrupt_status;
    case _(Status):
        return vnet->status;
    case _(ConfigGeneration):
        return VIRTIO_CONFIG_GENERATE;
    default:
        return ((uint32_t *) &vnet->config)[addr - _(Config)];
    }
#undef _
}

void virtio_net_write(virtio_net_state_t *vnet, uint32_t addr, uint32_t value)
{
    addr = addr >> 2;
#define _(reg) VIRTIO_##reg
    switch (addr) {
    case _(DeviceFeaturesSel):
        vnet->device_features_sel = value;
        break;
    case _(DriverFeatures):
        vnet->driver_features_sel == 0 ? (vnet->driver_features = value) : 0;
        break;
    case _(DriverFeaturesSel):
        vnet->driver_features_sel = value;
        break;
    case _(QueueSel):
        if (value < ARRAY_SIZE(vnet->queues))
            vnet->queue_sel = value;
        else
            virtio_net_set_fail(vnet);
        break;
    case _(QueueNum):
        if (value > 0 && value <= VNET_QUEUE_NUM_MAX)
            VNET_QUEUE.queue_num = value;
        else
            virtio_net_set_fail(vnet);
        break;
    case _(QueueReady):
        VNET_QUEUE.ready = value & 1;
        if (value & 1)
            VNET_QUEUE.last_avail = vnet->ram[VNET_QUEUE.queue_avail] >> 16;
        break;
    case _(QueueDescLow):
        VNET_QUEUE.queue_desc = vnet_preprocess(vnet, value);
        break;
    case _(QueueDescHigh):
        if (value)
            virtio_net_set_fail(vnet);
        break;
    case _(QueueDriverLow):
        VNET_QUEUE.queue_avail = vnet_preprocess(vnet, value);
        break;
    case _(QueueDriverHigh):
        if (value)
            virtio_net_set_fail(vnet);
        break;
    case _(QueueDeviceLow):
        VNET_QUEUE.queue_used = vnet_preprocess(vnet, value);
        break;
    case _(QueueDeviceHigh):
        if (value)
            virtio_net_set_fail(vnet);
        break;
    case _(QueueNotify):
        if (value < ARRAY_SIZE(vnet->queues))
            virtio_queue_notify_handler(vnet, value);
        else
            virtio_net_set_fail(vnet);
        break;
    case _(InterruptACK):
        vnet->interrupt_status &= ~value;
        break;
    case _(Status):
        virtio_net_update_status(vnet, value);
        break;
    default:
        ((uint32_t *) &vnet->config)[addr - _(Config)] = value;
        break;
    }
#undef _
}

static void virtio_net_init_config(virtio_net_state_t *vnet)
{
    memset(&vnet->config, 0, sizeof(vnet->config));
    vnet->config.mac[0] = 0x02;
    vnet->config.mac[1] = 0x00;
    vnet->config.mac[2] = 0x00;
    vnet->config.mac[3] = 0x00;
    vnet->config.mac[4] = 0x00;
    vnet->config.mac[5] = 0x01;
    vnet->config.status = VIRTIO_NET_S_LINK_UP;
}

void virtio_net_init(virtio_net_state_t *vnet, const char *tap_name)
{
    vnet->tap_fd = -1;
    vnet->device_features = 0;
    virtio_net_init_config(vnet);

#if defined(__linux__)
    if (tap_name && tap_name[0]) {
        struct ifreq ifr;
        int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
        if (fd < 0) {
            rv_log_error("Could not open /dev/net/tun: %s", strerror(errno));
            return;
        }

        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        strncpy(ifr.ifr_name, tap_name, IFNAMSIZ - 1);

        if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
            rv_log_error("TUNSETIFF(%s) failed: %s", tap_name,
                         strerror(errno));
            close(fd);
            return;
        }
        vnet->tap_fd = fd;
    }
#else
    (void) tap_name;
#endif
}
