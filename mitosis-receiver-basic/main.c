
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "app_uart.h"
#include "nrf_drv_uart.h"
#include "app_error.h"
#include "nrf_delay.h"
#include "nrf.h"
#include "nrf_gzll.h"
#include "mitosis-crypto.h"

#define MAX_TEST_DATA_BYTES     (15U)                /**< max number of test bytes to be used for tx and rx. */
#define UART_TX_BUF_SIZE 512                         /**< UART TX buffer size. */
#define UART_RX_BUF_SIZE 1                           /**< UART RX buffer size. */


#define RX_PIN_NUMBER  25
#define TX_PIN_NUMBER  24
#define CTS_PIN_NUMBER 23
#define RTS_PIN_NUMBER 22
#define HWFC           false


// ticks for inactive keyboard
#define INACTIVE 10000

// Binary printing
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x10 ? '#' : '.'), \
  (byte & 0x08 ? '#' : '.'), \
  (byte & 0x04 ? '#' : '.'), \
  (byte & 0x02 ? '#' : '.'), \
  (byte & 0x01 ? '#' : '.')

// Cryptographic keys and state
static mitosis_crypto_context_t left_crypto[3];
static mitosis_crypto_context_t right_crypto[3];
static mitosis_crypto_context_t receiver_crypto;
static volatile bool decrypting = false;

static bool process_left = true;

typedef enum _crypto_state_t {
    key_not_ready,
    seed_ready,
    new_key_ready,
    new_key_payload_ready
} crypto_state_t;

typedef struct _crypto_key_state_t {
    mitosis_crypto_seed_payload_t ack_payload;
    uint8_t seed[15];
    uint8_t seed_index;
    crypto_state_t state;
    uint8_t key_id;
    uint8_t new_key_id;
    bool key_id_confirmed;
} crypto_key_state_t;

crypto_key_state_t left_key_state;
crypto_key_state_t right_key_state;


// Data and acknowledgement payloads
static uint8_t data_payload_left[NRF_GZLL_CONST_MAX_PAYLOAD_LENGTH];  ///< Placeholder for data payload received from host.
static uint8_t data_payload_right[NRF_GZLL_CONST_MAX_PAYLOAD_LENGTH];  ///< Placeholder for data payload received from host.
static uint8_t data_buffer[11];

// Debug helper variables
extern nrf_gzll_error_code_t nrf_gzll_error_code;   ///< Error code
uint8_t c;

typedef struct _keyboard_stats_t {
    uint32_t cmac_fail;
    uint32_t decrypt_fail;
    uint32_t decrypt_collisions;
    uint32_t active;
    bool packet_received;
} keyboard_stats_t;

keyboard_stats_t left_stats = { 0 };
keyboard_stats_t right_stats = { 0 };

uint64_t counter = 0;

static inline
void key_state_init(crypto_key_state_t *state)
{
    memset(state, 0, sizeof(*state));
    state->state = key_not_ready;
    // Key ID 0 is special, and is always confirmed. This is necessary for key update to work.
    state->key_id_confirmed = true;
}

void mitosis_uart_handler(app_uart_evt_t * p_event)
{
    if (p_event->evt_type == APP_UART_DATA)
    {
        c = p_event->data.value;
        // detecting received packet from interupt, and unpacking
        if (left_stats.packet_received)
        {
            left_stats.packet_received = false;

            data_buffer[0] = ((data_payload_left[0] & 1<<3) ? 1:0) << 0 |
                             ((data_payload_left[0] & 1<<4) ? 1:0) << 1 |
                             ((data_payload_left[0] & 1<<5) ? 1:0) << 2 |
                             ((data_payload_left[0] & 1<<6) ? 1:0) << 3 |
                             ((data_payload_left[0] & 1<<7) ? 1:0) << 4;

            data_buffer[2] = ((data_payload_left[1] & 1<<6) ? 1:0) << 0 |
                             ((data_payload_left[1] & 1<<7) ? 1:0) << 1 |
                             ((data_payload_left[0] & 1<<0) ? 1:0) << 2 |
                             ((data_payload_left[0] & 1<<1) ? 1:0) << 3 |
                             ((data_payload_left[0] & 1<<2) ? 1:0) << 4;

            data_buffer[4] = ((data_payload_left[1] & 1<<1) ? 1:0) << 0 |
                             ((data_payload_left[1] & 1<<2) ? 1:0) << 1 |
                             ((data_payload_left[1] & 1<<3) ? 1:0) << 2 |
                             ((data_payload_left[1] & 1<<4) ? 1:0) << 3 |
                             ((data_payload_left[1] & 1<<5) ? 1:0) << 4;

            data_buffer[6] = ((data_payload_left[2] & 1<<5) ? 1:0) << 1 |
                             ((data_payload_left[2] & 1<<6) ? 1:0) << 2 |
                             ((data_payload_left[2] & 1<<7) ? 1:0) << 3 |
                             ((data_payload_left[1] & 1<<0) ? 1:0) << 4;

            data_buffer[8] = ((data_payload_left[2] & 1<<1) ? 1:0) << 1 |
                             ((data_payload_left[2] & 1<<2) ? 1:0) << 2 |
                             ((data_payload_left[2] & 1<<3) ? 1:0) << 3 |
                             ((data_payload_left[2] & 1<<4) ? 1:0) << 4;
        }

        if (right_stats.packet_received)
        {
            right_stats.packet_received = false;

            data_buffer[1] = ((data_payload_right[0] & 1<<7) ? 1:0) << 0 |
                             ((data_payload_right[0] & 1<<6) ? 1:0) << 1 |
                             ((data_payload_right[0] & 1<<5) ? 1:0) << 2 |
                             ((data_payload_right[0] & 1<<4) ? 1:0) << 3 |
                             ((data_payload_right[0] & 1<<3) ? 1:0) << 4;

            data_buffer[3] = ((data_payload_right[0] & 1<<2) ? 1:0) << 0 |
                             ((data_payload_right[0] & 1<<1) ? 1:0) << 1 |
                             ((data_payload_right[0] & 1<<0) ? 1:0) << 2 |
                             ((data_payload_right[1] & 1<<7) ? 1:0) << 3 |
                             ((data_payload_right[1] & 1<<6) ? 1:0) << 4;

            data_buffer[5] = ((data_payload_right[1] & 1<<5) ? 1:0) << 0 |
                             ((data_payload_right[1] & 1<<4) ? 1:0) << 1 |
                             ((data_payload_right[1] & 1<<3) ? 1:0) << 2 |
                             ((data_payload_right[1] & 1<<2) ? 1:0) << 3 |
                             ((data_payload_right[1] & 1<<1) ? 1:0) << 4;

            data_buffer[7] = ((data_payload_right[1] & 1<<0) ? 1:0) << 0 |
                             ((data_payload_right[2] & 1<<7) ? 1:0) << 1 |
                             ((data_payload_right[2] & 1<<6) ? 1:0) << 2 |
                             ((data_payload_right[2] & 1<<5) ? 1:0) << 3;

            data_buffer[9] = ((data_payload_right[2] & 1<<4) ? 1:0) << 0 |
                             ((data_payload_right[2] & 1<<3) ? 1:0) << 1 |
                             ((data_payload_right[2] & 1<<2) ? 1:0) << 2 |
                             ((data_payload_right[2] & 1<<1) ? 1:0) << 3;
        }
        if (p_event->data.value == 's')
        {
            // sending data to QMK, and an end byte
            nrf_drv_uart_tx(data_buffer,11);
            // debugging help, for printing keystates to a serial console
            /*
            printf(BYTE_TO_BINARY_PATTERN " " \
                   BYTE_TO_BINARY_PATTERN " " \
                   BYTE_TO_BINARY_PATTERN " " \
                   BYTE_TO_BINARY_PATTERN " " \
                   BYTE_TO_BINARY_PATTERN " " \
                   BYTE_TO_BINARY_PATTERN " " \
                   BYTE_TO_BINARY_PATTERN " " \
                   BYTE_TO_BINARY_PATTERN " " \
                   BYTE_TO_BINARY_PATTERN " " \
                   BYTE_TO_BINARY_PATTERN "\r\n", \
                   BYTE_TO_BINARY(data_buffer[0]), \
                   BYTE_TO_BINARY(data_buffer[1]), \
                   BYTE_TO_BINARY(data_buffer[2]), \
                   BYTE_TO_BINARY(data_buffer[3]), \
                   BYTE_TO_BINARY(data_buffer[4]), \
                   BYTE_TO_BINARY(data_buffer[5]), \
                   BYTE_TO_BINARY(data_buffer[6]), \
                   BYTE_TO_BINARY(data_buffer[7]), \
                   BYTE_TO_BINARY(data_buffer[8]), \
                   BYTE_TO_BINARY(data_buffer[9]));
            nrf_delay_us(100);
            */
            // Give the UART time to read the buffer before it changes.
            nrf_delay_us(10);
        }
        // if no packets recieved from keyboards in a few seconds, assume either
        // out of range, or sleeping due to no keys pressed, update keystates to off
        left_stats.active++;
        right_stats.active++;
        if (left_stats.active > INACTIVE)
        {
            data_buffer[0] = 0;
            data_buffer[2] = 0;
            data_buffer[4] = 0;
            data_buffer[6] = 0;
            data_buffer[8] = 0;
            left_stats.active = 0;
        }
        if (right_stats.active > INACTIVE)
        {
            data_buffer[1] = 0;
            data_buffer[3] = 0;
            data_buffer[5] = 0;
            data_buffer[7] = 0;
            data_buffer[9] = 0;
            right_stats.active = 0;
        }
    }
    else if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_communication);
    }
}

static inline
void update_key_state(crypto_key_state_t *key_state, mitosis_crypto_context_t crypto_contexts[], mitosis_crypto_key_type_t key_type)
{
    switch (key_state->state)
    {
        case key_not_ready:
            // Check if a random value is needed and if the RNG is ready and consume it.
            if (key_state->seed_index < sizeof(key_state->seed) && NRF_RNG->EVENTS_VALRDY)
            {
                key_state->seed[key_state->seed_index++] = NRF_RNG->VALUE;
                NRF_RNG->EVENTS_VALRDY = 0;
                if (key_state->seed_index == sizeof(key_state->seed))
                {
                    memcpy(key_state->ack_payload.seed, key_state->seed, sizeof(key_state->seed));
                    key_state->seed_index = 0;
                    key_state->state = seed_ready;
                    key_state->new_key_id = key_state->key_id + 1;
                    if (key_state->new_key_id == 0)
                    {
                        // Key id 0 is special (it's the initial key), so skip it.
                        key_state->new_key_id = 1;
                    }
                }
            }
            break;
        case seed_ready:
            if (!decrypting)
            {
                decrypting = true;
                if (mitosis_crypto_rekey(&crypto_contexts[(key_state->new_key_id & 0x1) + 1], key_type, key_state->ack_payload.seed, sizeof(key_state->ack_payload.seed)))
                {
                    key_state->state = new_key_ready;
                }
                decrypting = false;
            }
            break;
        case new_key_ready:
            if (!decrypting)
            {
                decrypting = true;
                receiver_crypto.encrypt.ctr.iv.counter = key_state->ack_payload.key_id = key_state->new_key_id;
                if (mitosis_aes_ctr_encrypt(&receiver_crypto.encrypt, sizeof(key_state->ack_payload.seed), key_state->ack_payload.seed, key_state->ack_payload.seed) &&
                    mitosis_cmac_compute(&receiver_crypto.cmac, key_state->ack_payload.payload, sizeof(key_state->ack_payload.payload), key_state->ack_payload.mac))
                {
                    key_state->state = new_key_payload_ready;
                }
                decrypting = false;
            }
            break;
        default:
            break;
    }
}


int main(void)
{
    uint32_t err_code;

    // Enable error correction in the RNG module.
    NRF_RNG->CONFIG |= RNG_CONFIG_DERCEN_Msk;
    // Tell the RNG to start running.
    NRF_RNG->EVENTS_VALRDY = 0;
    NRF_RNG->TASKS_START = 1;

    // Initialize crypto keys
    mitosis_crypto_init(&left_crypto[0], left_keyboard_crypto_key);
    mitosis_crypto_init(&right_crypto[0], right_keyboard_crypto_key);
    mitosis_crypto_init(&receiver_crypto, receiver_crypto_key);

    key_state_init(&left_key_state);
    key_state_init(&right_key_state);

    memset(data_buffer, 0, sizeof(data_buffer));
    data_buffer[10] = 0xE0;
    const app_uart_comm_params_t comm_params =
      {
          RX_PIN_NUMBER,
          TX_PIN_NUMBER,
          RTS_PIN_NUMBER,
          CTS_PIN_NUMBER,
          APP_UART_FLOW_CONTROL_DISABLED,
          false,
          UART_BAUDRATE_BAUDRATE_Baud1M
      };

    APP_UART_INIT(&comm_params,
                  mitosis_uart_handler,
                  APP_IRQ_PRIORITY_HIGH,
                  err_code);

    APP_ERROR_CHECK(err_code);

    // Initialize Gazell
    nrf_gzll_init(NRF_GZLL_MODE_HOST);

    // Addressing
    nrf_gzll_set_base_address_0(0x01020304);
    nrf_gzll_set_base_address_1(0x05060708);

    // Enable Gazell to start sending over the air
    nrf_gzll_enable();

    // main loop
    while (true)
    {
        if (process_left)
        {
            update_key_state(&left_key_state, left_crypto, left_keyboard_crypto_key);
        }
        else
        {
            update_key_state(&right_key_state, right_crypto, right_keyboard_crypto_key);
        }
        // This flip/flops between next key generation for the left and right halves.
        process_left = !process_left;
        counter++;
    }
}


void process_received_packet(mitosis_crypto_context_t crypto[], crypto_key_state_t* key_state, mitosis_crypto_data_payload_t *payload, keyboard_stats_t *stats, uint8_t *decrypted_payload, mitosis_crypto_seed_payload_t **ack_payload, uint32_t *ack_payload_length)
{
    uint8_t mac_scratch[MITOSIS_CMAC_OUTPUT_SIZE];
    if (!decrypting)
    {
        decrypting = true;
        uint8_t index = (payload->key_id == 0) ? 0 : (payload->key_id & 0x1) + 1;
        mitosis_cmac_compute(&crypto[index].cmac, payload->payload, sizeof(payload->payload), mac_scratch);
        if (memcmp(payload->mac, mac_scratch, sizeof(payload->mac)) == 0)
        {
            // This is a valid message from the left keyboard; decrypt it.
            crypto[index].encrypt.ctr.iv.counter = payload->counter;
            if (mitosis_aes_ctr_decrypt(&crypto[index].encrypt, sizeof(payload->data), payload->data, decrypted_payload))
            {
                stats->packet_received = true;
                stats->active = 0;
                if (key_state->new_key_id != key_state->key_id && key_state->new_key_id == payload->key_id)
                {
                    key_state->key_id_confirmed = true;
                    key_state->key_id = key_state->new_key_id;
                    // On confirmation, generate new key
                    key_state->state = key_not_ready;
                }
                if ((payload->key_id == 0 || payload->counter > MITOSIS_REKEY_INTERVAL) && key_state->key_id_confirmed && key_state->state == new_key_payload_ready)
                {
                    *ack_payload = &key_state->ack_payload;
                    *ack_payload_length = sizeof(key_state->ack_payload);
                }
            }
            else
            {
                ++stats->decrypt_fail;
            }
        }
        else
        {
            ++stats->cmac_fail;
            if (key_state->state == new_key_payload_ready)
            {
                // re-send the existing seed in case the keyboard reset and forgot.
                *ack_payload = &key_state->ack_payload;
                *ack_payload_length = sizeof(key_state->ack_payload);
            }
        }
        decrypting = false;
    }
    else
    {
        ++stats->decrypt_collisions;
    }
}


// Callbacks not needed in this example.
void nrf_gzll_device_tx_success(uint32_t pipe, nrf_gzll_device_tx_info_t tx_info) {}
void nrf_gzll_device_tx_failed(uint32_t pipe, nrf_gzll_device_tx_info_t tx_info) {}
void nrf_gzll_disabled() {}

// If a data packet was received, identify half, and throw flag
void nrf_gzll_host_rx_data_ready(uint32_t pipe, nrf_gzll_host_rx_info_t rx_info)
{
    mitosis_crypto_data_payload_t payload;
    uint32_t payload_length = sizeof(payload);
    uint32_t ack_payload_length = 0;
    mitosis_crypto_seed_payload_t *ack_payload = NULL;

    if (pipe == 0)
    {
        // Pop packet and write payload to temp storage for verification.
        nrf_gzll_fetch_packet_from_rx_fifo(pipe, (uint8_t*) &payload, &payload_length);
        // If a crypto operation is in-progress, just ack the payload and continue.
        // This could cause missing keypresses, so consider queueing the payload
        // and process it as soon as this is complete.
        process_received_packet(left_crypto, &left_key_state, &payload, &left_stats, data_payload_left, &ack_payload, &ack_payload_length);
    }
    else if (pipe == 1)
    {
        // Pop packet and write payload to temp storage for verification.
        nrf_gzll_fetch_packet_from_rx_fifo(pipe, (uint8_t*) &payload, &payload_length);
        // If a crypto operation is in-progress, just ack the payload and continue.
        // This could cause missing keypresses, so consider queueing the payload
        // and process it as soon as this is complete.
        process_received_packet(right_crypto, &right_key_state, &payload, &right_stats, data_payload_right, &ack_payload, &ack_payload_length);
    }

    // not sure if required, I guess if enough packets are missed during blocking uart
    nrf_gzll_flush_rx_fifo(pipe);

    //load ACK payload into TX queue
    if (ack_payload != NULL)
    {
        nrf_gzll_add_packet_to_tx_fifo(pipe, (uint8_t*) ack_payload, ack_payload_length);
    }
}
