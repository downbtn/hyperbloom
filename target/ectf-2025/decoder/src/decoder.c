/**
 * @file    decoder.c
 * @author  Samuel Meyers, Daniel Ha
 * @brief   eCTF Hardware-Insecure Example implementation
 * @date    2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation, with changes (c) 2025 Daniel Ha
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"

#include "crypto.h"
#include "host_messaging.h"
#include "simple_flash.h"
#include "simple_uart.h"
#include "secrets.h"

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define MAX_PACKET_SIZE 132 // frame decode
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define VALID_MAGIC 0x39393939
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))


/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html
//
typedef struct {
    timestamp_t timestamp;
    channel_id_t channel;
    uint32_t frame_len;
    uint8_t data[FRAME_SIZE];
} decrypted_frame_t;
_Static_assert(sizeof(decrypted_frame_t) == 80, "sizeof(decrypted_frame_t)");

typedef struct {
    channel_id_t channel;
    uint8_t iv[16];
    uint8_t encrypted_frame[sizeof(decrypted_frame_t)];
    uint8_t mac[32];
} frame_packet_t;
_Static_assert(sizeof(frame_packet_t) == 132, "sizeof(frame_packet_t)");

typedef struct {
    uint32_t device_id;
    uint64_t start;
    uint64_t end;
    uint32_t channel;
    uint8_t key[32];
} decrypted_subscription_t;
_Static_assert(sizeof(decrypted_subscription_t) == 56, "sizeof(decrypted_subscription_t)");

typedef struct {
    uint8_t iv[16];
    uint8_t encrypted_sub[sizeof(decrypted_subscription_t)];
    uint8_t mac[32];
} subscription_update_packet_t;
_Static_assert(sizeof(subscription_update_packet_t) == 104, "sizeof(subscription_update_packet_t)");

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    uint32_t magic;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    uint8_t key[32];
} channel_status_t;


typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
*/
int list_channels() {
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].magic == VALID_MAGIC) {
            resp.channel_info[resp.n_channels].channel =  decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    write_packet(LIST_MSG, &resp, len);
    return 0;
}


/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet
 *  @param update A pointer to an array of channel_update structs,
 *      which contains the channel number, start, and end timestamps
 *      for each channel being updated.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
*/
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    int i;
    
    // Verify MAC of IV & ciphertext
    uint8_t hmac[sizeof(update->mac)];
    const uint32_t size_to_mac = sizeof(update->iv) + sizeof(update->encrypted_sub);
    _Static_assert(size_to_mac == 72);
    compute_hmac((const uint8_t *)update, sizeof(update->iv) + sizeof(update->encrypted_sub), SUBSCRIPTION_KEY, hmac);

    // vulnerable to timing attack!
    if (memcmp(hmac, update->mac, sizeof(hmac)) != 0) {
        STATUS_LED_ERROR();
        print_error("Subscription HMAC does not match\n");
        return -1;
    }

    // Decrypt subscription body
    uint8_t decrypted_data[sizeof(update->encrypted_sub)];
    decrypt_sym(update->encrypted_sub, sizeof(decrypted_data), update->iv, SUBSCRIPTION_KEY, decrypted_data);

    decrypted_subscription_t *decrypted_sub = (decrypted_subscription_t *)decrypted_data;

    if (decrypted_sub->device_id != DECODER_ID) {
        STATUS_LED_ERROR();
        print_error("Decoder ID mismatch\n");
        return -1;
    }

    if (decrypted_sub->start > decrypted_sub->end) {
        STATUS_LED_ERROR();
        print_error("Invalid start/end range\n");
        return -1;
    }

    // Find the first empty slot in the subscription array
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == decrypted_sub->channel || decoder_status.subscribed_channels[i].magic != VALID_MAGIC) {
            decoder_status.subscribed_channels[i].magic = VALID_MAGIC;
            decoder_status.subscribed_channels[i].id = decrypted_sub->channel;
            decoder_status.subscribed_channels[i].start_timestamp = decrypted_sub->start;
            decoder_status.subscribed_channels[i].end_timestamp = decrypted_sub->end;
            memcpy(&decoder_status.subscribed_channels[i].key, decrypted_sub->key, sizeof(decrypted_sub->key));
            break;
        }
    }

    // If we do not have any room for more subscriptions
    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    // Success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
*/
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    // Get channel key
    const uint8_t *key;
    timestamp_t start;
    timestamp_t end;

    if (new_frame->channel == EMERGENCY_CHANNEL) {
        key = EMERGENCY_KEY;
        start = 0;
        end = UINT64_MAX;
    } else {
        uint16_t i;
        for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
            if (decoder_status.subscribed_channels[i].magic == VALID_MAGIC && decoder_status.subscribed_channels[i].id == new_frame->channel) {
                key = decoder_status.subscribed_channels[i].key;
                start = decoder_status.subscribed_channels[i].start_timestamp;
                end = decoder_status.subscribed_channels[i].end_timestamp;
                break;
            }
        }

        if (i == MAX_CHANNEL_COUNT) {
            // no subscription for that channel
            STATUS_LED_RED();
            print_error("No subscription on that channel\n");
            return -1;
        }
    }

    // Verify HMAC    
    uint8_t hmac[sizeof(new_frame->mac)];
    const uint32_t size_to_mac = sizeof(new_frame->iv) + sizeof(new_frame->channel) + sizeof(new_frame->encrypted_frame);
    _Static_assert(size_to_mac == 100);
    compute_hmac((const uint8_t *)new_frame, size_to_mac, key, hmac);
    
    if (memcmp(hmac, new_frame->mac, sizeof(hmac)) != 0) {
        STATUS_LED_RED();
        print_error("Frame HMAC does not match!\n");
        return -1;
    }

    // Attempt decryption of frame data
    decrypted_frame_t dec;
    decrypt_sym((const uint8_t *) new_frame->encrypted_frame, sizeof(new_frame->encrypted_frame), (const uint8_t *)new_frame->iv, key, (uint8_t *) &dec);

    if (dec.frame_len > FRAME_SIZE) {
        STATUS_LED_RED();
        print_error("Frame data length too large (corrupted frame?)\n");
        return -1;
    }

    if (new_frame->channel != dec.channel) {
        STATUS_LED_RED();
        print_error("Channel ID mismatch (corrupted frame?)\n");
        return -1;
    }

    if (dec.timestamp < start) {
        STATUS_LED_RED();
        print_error("Frame timestamp too early\n");
        return -1;
    }

    if (dec.timestamp > end) {
        STATUS_LED_RED();
        print_error("Frame timestamp too late\n");
        return -1;
    }

    write_packet(DECODE_MSG, dec.data, dec.frame_len);
    return 0;
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        print_debug("First boot.  Setting flash...\n");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].magic = 0;
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[MAX_PACKET_SIZE];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    print_debug("Decoder Booted!\n");

    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len, MAX_PACKET_SIZE);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
