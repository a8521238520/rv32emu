/*
 * rv32emu is freely redistributable under the MIT License. See the file
 * "LICENSE" for information on usage and redistribution of this file.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtio.h"

#define VRNG_FEATURES_0 0
#define VRNG_FEATURES_1 1 /* VIRTIO_F_VERSION_1 */

#define VRNG_QUEUE_NUM_MAX 1024
#define VRNG_QUEUE (vrng->queues[vrng->queue_sel])

static void virtio_rng_set_fail(virtio_rng_state_t *vrng)
{
    vrng->status |= VIRTIO_STATUS_DEVICE_NEEDS_RESET;
    if (vrng->status & VIRTIO_STATUS_DRIVER_OK)
        vrng->interrupt_status |= VIRTIO_INT_CONF_CHANGE;
}

static inline uint32_t vrng_preprocess(virtio_rng_state_t *vrng,
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
        virtio_rng_set_fail(vrng);
        return 0;
    }

    return addr >> 2;
}

static void virtio_rng_update_status(virtio_rng_state_t *vrng, uint32_t status)
{
    vrng->status |= status;
    if (status)
        return;

    /* Reset */
    uint32_t *ram = vrng->ram;
    int rng_fd = vrng->rng_fd;
    memset(vrng, 0, sizeof(*vrng));
    vrng->ram = ram;
    vrng->rng_fd = rng_fd;
}

static ssize_t virtio_rng_read_entropy(virtio_rng_state_t *vrng,
                                       void *buffer,
                                       size_t length)
{
#if defined(__EMSCRIPTEN__)
    uint8_t *bytes = buffer;
    for (size_t i = 0; i < length; i++)
        bytes[i] = (uint8_t) (rand() & 0xff);
    return (ssize_t) length;
#else
    if (vrng->rng_fd < 0)
        return -1;
    return read(vrng->rng_fd, buffer, length);
#endif
}

static void virtio_queue_notify_handler(virtio_rng_state_t *vrng,
                                        virtio_rng_queue_t *queue)
{
    uint32_t *ram = vrng->ram;
    if (vrng->status & VIRTIO_STATUS_DEVICE_NEEDS_RESET)
        return;

    if (!((vrng->status & VIRTIO_STATUS_DRIVER_OK) && queue->ready))
        return virtio_rng_set_fail(vrng);

    /* Calculate available ring index */
    uint16_t queue_idx = queue->last_avail % queue->queue_num;
    uint16_t buffer_idx =
        ram[queue->queue_avail + 1 + queue_idx / 2] >> (16 * (queue_idx % 2));

    /* Update available ring pointer */
    VRNG_QUEUE.last_avail++;

    /* Read descriptor */
    struct virtq_desc *vq_desc =
        (struct virtq_desc *) &vrng->ram[queue->queue_desc + buffer_idx * 4];

    /* Write entropy buffer */
    void *entropy_buf =
        (void *) ((uintptr_t) vrng->ram + (uintptr_t) vq_desc->addr);
    ssize_t total = virtio_rng_read_entropy(vrng, entropy_buf, vq_desc->len);
    if (total < 0) {
        rv_log_error("virtio-rng read failed: %s", strerror(errno));
        return virtio_rng_set_fail(vrng);
    }

    /* Clear write flag */
    vq_desc->flags = 0;

    /* Get virtq_used.idx (le16) */
    uint16_t used = ram[queue->queue_used] >> 16;

    /* Update used ring information */
    uint32_t vq_used_addr =
        VRNG_QUEUE.queue_used + 1 + (used % queue->queue_num) * 2;
    ram[vq_used_addr] = buffer_idx;
    ram[vq_used_addr + 1] = (uint32_t) total;
    used++;

    /* Reset used ring flag to zero (virtq_used.flags) */
    vrng->ram[VRNG_QUEUE.queue_used] &= MASK(16);

    /* Update the used ring pointer (virtq_used.idx) */
    vrng->ram[VRNG_QUEUE.queue_used] |= ((uint32_t) used) << 16;

    /* Send interrupt, unless VIRTQ_AVAIL_F_NO_INTERRUPT is set */
    if (!(ram[VRNG_QUEUE.queue_avail] & 1))
        vrng->interrupt_status |= VIRTIO_INT_USED_RING;
}

uint32_t virtio_rng_read(virtio_rng_state_t *vrng, uint32_t addr)
{
    addr = addr >> 2;
#define _(reg) VIRTIO_##reg
    switch (addr) {
    case _(MagicValue):
        return VIRTIO_MAGIC_NUMBER;
    case _(Version):
        return VIRTIO_VERSION;
    case _(DeviceID):
        return VIRTIO_RNG_DEV_ID;
    case _(VendorID):
        return VIRTIO_VENDOR_ID;
    case _(DeviceFeatures):
        return vrng->device_features_sel == 0
                   ? VRNG_FEATURES_0
                   : (vrng->device_features_sel == 1 ? VRNG_FEATURES_1 : 0);
    case _(QueueNumMax):
        return VRNG_QUEUE_NUM_MAX;
    case _(QueueReady):
        return (uint32_t) VRNG_QUEUE.ready;
    case _(InterruptStatus):
        return vrng->interrupt_status;
    case _(Status):
        return vrng->status;
    case _(ConfigGeneration):
        return VIRTIO_CONFIG_GENERATE;
    default:
        /* No other readable registers */
        return 0;
    }
#undef _
}

void virtio_rng_write(virtio_rng_state_t *vrng, uint32_t addr, uint32_t value)
{
    addr = addr >> 2;
#define _(reg) VIRTIO_##reg
    switch (addr) {
    case _(DeviceFeaturesSel):
        vrng->device_features_sel = value;
        break;
    case _(DriverFeatures):
        vrng->driver_features_sel == 0 ? (vrng->driver_features = value) : 0;
        break;
    case _(DriverFeaturesSel):
        vrng->driver_features_sel = value;
        break;
    case _(QueueSel):
        if (value < ARRAY_SIZE(vrng->queues))
            vrng->queue_sel = value;
        else
            virtio_rng_set_fail(vrng);
        break;
    case _(QueueNum):
        if (value > 0 && value <= VRNG_QUEUE_NUM_MAX)
            VRNG_QUEUE.queue_num = value;
        else
            virtio_rng_set_fail(vrng);
        break;
    case _(QueueReady):
        VRNG_QUEUE.ready = value & 1;
        if (value & 1)
            VRNG_QUEUE.last_avail = vrng->ram[VRNG_QUEUE.queue_avail] >> 16;
        break;
    case _(QueueDescLow):
        VRNG_QUEUE.queue_desc = vrng_preprocess(vrng, value);
        break;
    case _(QueueDescHigh):
        if (value)
            virtio_rng_set_fail(vrng);
        break;
    case _(QueueDriverLow):
        VRNG_QUEUE.queue_avail = vrng_preprocess(vrng, value);
        break;
    case _(QueueDriverHigh):
        if (value)
            virtio_rng_set_fail(vrng);
        break;
    case _(QueueDeviceLow):
        VRNG_QUEUE.queue_used = vrng_preprocess(vrng, value);
        break;
    case _(QueueDeviceHigh):
        if (value)
            virtio_rng_set_fail(vrng);
        break;
    case _(QueueNotify):
        if (value < ARRAY_SIZE(vrng->queues))
            virtio_queue_notify_handler(vrng, &VRNG_QUEUE);
        else
            virtio_rng_set_fail(vrng);
        break;
    case _(InterruptACK):
        vrng->interrupt_status &= ~value;
        break;
    case _(Status):
        virtio_rng_update_status(vrng, value);
        break;
    default:
        /* No other writable registers */
        virtio_rng_set_fail(vrng);
        break;
    }
#undef _
}

void virtio_rng_init(virtio_rng_state_t *vrng)
{
#if defined(__EMSCRIPTEN__)
    vrng->rng_fd = -1;
#else
    vrng->rng_fd = open("/dev/random", O_RDONLY);
    if (vrng->rng_fd < 0) {
        rv_log_error("Could not open /dev/random: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
#endif
}
