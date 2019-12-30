
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


// Define payload length
#define TX_PAYLOAD_LENGTH sizeof(mitosis_crypto_data_payload_t) ///< 24 byte payload length

// ticks for inactive keyboard
#define INACTIVE 10000
//100000

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
static mitosis_crypto_context_t right_crypto;
static mitosis_crypto_context_t receiver_crypto;
static volatile bool decrypting = false;
static uint8_t left_key_id = 0;
static bool left_key_id_confirmed = true; // key_id 0 is always "confirmed"
static uint8_t new_left_key_id = 0;

static uint8_t seed[15];
static uint8_t seed_index = 0;
static bool process_left = true;

typedef enum _crypto_state_t {
    key_not_ready,
    seed_ready,
    prk_ready,
    encrypt_key_ready,
    encrypt_nonce_ready,
    mac_key_ready,
    new_key_ready,
    new_key_payload_ready
} crypto_state_t;

volatile crypto_state_t crypto_state;


// Data and acknowledgement payloads
static uint8_t data_payload_left[NRF_GZLL_CONST_MAX_PAYLOAD_LENGTH];  ///< Placeholder for data payload received from host.
static uint8_t data_payload_right[NRF_GZLL_CONST_MAX_PAYLOAD_LENGTH];  ///< Placeholder for data payload received from host.
static mitosis_crypto_seed_payload_t ack_payload;                      ///< Payload to attach to ACK sent to device.
static uint8_t data_buffer[11];

// Debug helper variables
extern nrf_gzll_error_code_t nrf_gzll_error_code;   ///< Error code
static bool packet_received_left, packet_received_right;
uint32_t left_active = 0;
uint32_t right_active = 0;
uint8_t c;
uint32_t decrypt_collisions = 0;
uint32_t left_cmac_fail = 0;
uint32_t right_cmac_fail = 0;
uint32_t left_decrypt_fail = 0;
uint32_t right_decrypt_fail = 0;
uint32_t rng_insufficient = 0;
uint32_t uart_full = 0;


void mitosis_uart_handler(app_uart_evt_t * p_event)
{
    if (p_event->evt_type == APP_UART_DATA)
    {
        // detecting received packet from interupt, and unpacking
        if (packet_received_left)
        {
            packet_received_left = false;

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

        if (packet_received_right)
        {
            packet_received_right = false;

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
            // app_uart_put(0xE0);
            // This might be slower than the old method, which might be causing multi-key to fail.
            // for (uint32_t i = 0; i < sizeof(data_buffer); i++)
            // {
            //     app_uart_put(data_buffer[i]);
            // }
            // app_uart_put(0xE0);
            nrf_delay_us(10);
        }
        // if no packets recieved from keyboards in a few seconds, assume either
        // out of range, or sleeping due to no keys pressed, update keystates to off
        left_active++;
        right_active++;
        if (left_active > INACTIVE)
        {
            data_buffer[0] = 0;
            data_buffer[2] = 0;
            data_buffer[4] = 0;
            data_buffer[6] = 0;
            data_buffer[8] = 0;
            left_active = 0;
        }
        if (right_active > INACTIVE)
        {
            data_buffer[1] = 0;
            data_buffer[3] = 0;
            data_buffer[5] = 0;
            data_buffer[7] = 0;
            data_buffer[9] = 0;
            right_active = 0;
        }
    }
    // else if (p_event->evt_type == APP_UART_TX_EMPTY)
    // {
    //     app_uart_put(0xE0);
    // }
    else if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_communication);
    }
    else if (p_event->evt_type == APP_UART_FIFO_ERROR)
    {
        if (p_event->data.error_code == NRF_ERROR_NO_MEM)
        {
            ++uart_full;
            app_uart_flush();
            // app_uart_put(0xE0);
            memset(data_buffer, 0, sizeof(data_buffer));
        }
        else
        {
            APP_ERROR_HANDLER(p_event->data.error_code);
        }
    }
}


int main(void)
{
    uint32_t err_code;
    uint8_t prk[MITOSIS_HMAC_OUTPUT_SIZE];
    const uint8_t left_salt[sizeof((uint8_t[]) MITOSIS_LEFT_SALT)] = MITOSIS_LEFT_SALT;
    crypto_state = key_not_ready;

    // Enable error correction in the RNG module.
    NRF_RNG->CONFIG |= RNG_CONFIG_DERCEN_Msk;
    // Tell the RNG to start running.
    NRF_RNG->EVENTS_VALRDY = 0;
    NRF_RNG->TASKS_START = 1;

    // Initialize crypto keys
    mitosis_crypto_init(&left_crypto[0], left_keyboard_crypto_key);
    mitosis_crypto_init(&right_crypto, right_keyboard_crypto_key);
    mitosis_crypto_init(&receiver_crypto, receiver_crypto_key);

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

    // Load data into TX queue
    // ack_payload[0] = 0x55;
    // nrf_gzll_add_packet_to_tx_fifo(0, data_payload_left, TX_PAYLOAD_LENGTH);
    // nrf_gzll_add_packet_to_tx_fifo(1, data_payload_left, TX_PAYLOAD_LENGTH);

    // Enable Gazell to start sending over the air
    nrf_gzll_enable();

    // main loop
    while (true)
    {
        // // detecting received packet from interupt, and unpacking
        // if (packet_received_left)
        // {
        //     packet_received_left = false;
        //
        //     data_buffer[0] = ((data_payload_left[0] & 1<<3) ? 1:0) << 0 |
        //                      ((data_payload_left[0] & 1<<4) ? 1:0) << 1 |
        //                      ((data_payload_left[0] & 1<<5) ? 1:0) << 2 |
        //                      ((data_payload_left[0] & 1<<6) ? 1:0) << 3 |
        //                      ((data_payload_left[0] & 1<<7) ? 1:0) << 4;
        //
        //     data_buffer[2] = ((data_payload_left[1] & 1<<6) ? 1:0) << 0 |
        //                      ((data_payload_left[1] & 1<<7) ? 1:0) << 1 |
        //                      ((data_payload_left[0] & 1<<0) ? 1:0) << 2 |
        //                      ((data_payload_left[0] & 1<<1) ? 1:0) << 3 |
        //                      ((data_payload_left[0] & 1<<2) ? 1:0) << 4;
        //
        //     data_buffer[4] = ((data_payload_left[1] & 1<<1) ? 1:0) << 0 |
        //                      ((data_payload_left[1] & 1<<2) ? 1:0) << 1 |
        //                      ((data_payload_left[1] & 1<<3) ? 1:0) << 2 |
        //                      ((data_payload_left[1] & 1<<4) ? 1:0) << 3 |
        //                      ((data_payload_left[1] & 1<<5) ? 1:0) << 4;
        //
        //     data_buffer[6] = ((data_payload_left[2] & 1<<5) ? 1:0) << 1 |
        //                      ((data_payload_left[2] & 1<<6) ? 1:0) << 2 |
        //                      ((data_payload_left[2] & 1<<7) ? 1:0) << 3 |
        //                      ((data_payload_left[1] & 1<<0) ? 1:0) << 4;
        //
        //     data_buffer[8] = ((data_payload_left[2] & 1<<1) ? 1:0) << 1 |
        //                      ((data_payload_left[2] & 1<<2) ? 1:0) << 2 |
        //                      ((data_payload_left[2] & 1<<3) ? 1:0) << 3 |
        //                      ((data_payload_left[2] & 1<<4) ? 1:0) << 4;
        // }
        //
        // if (packet_received_right)
        // {
        //     packet_received_right = false;
        //
        //     data_buffer[1] = ((data_payload_right[0] & 1<<7) ? 1:0) << 0 |
        //                      ((data_payload_right[0] & 1<<6) ? 1:0) << 1 |
        //                      ((data_payload_right[0] & 1<<5) ? 1:0) << 2 |
        //                      ((data_payload_right[0] & 1<<4) ? 1:0) << 3 |
        //                      ((data_payload_right[0] & 1<<3) ? 1:0) << 4;
        //
        //     data_buffer[3] = ((data_payload_right[0] & 1<<2) ? 1:0) << 0 |
        //                      ((data_payload_right[0] & 1<<1) ? 1:0) << 1 |
        //                      ((data_payload_right[0] & 1<<0) ? 1:0) << 2 |
        //                      ((data_payload_right[1] & 1<<7) ? 1:0) << 3 |
        //                      ((data_payload_right[1] & 1<<6) ? 1:0) << 4;
        //
        //     data_buffer[5] = ((data_payload_right[1] & 1<<5) ? 1:0) << 0 |
        //                      ((data_payload_right[1] & 1<<4) ? 1:0) << 1 |
        //                      ((data_payload_right[1] & 1<<3) ? 1:0) << 2 |
        //                      ((data_payload_right[1] & 1<<2) ? 1:0) << 3 |
        //                      ((data_payload_right[1] & 1<<1) ? 1:0) << 4;
        //
        //     data_buffer[7] = ((data_payload_right[1] & 1<<0) ? 1:0) << 0 |
        //                      ((data_payload_right[2] & 1<<7) ? 1:0) << 1 |
        //                      ((data_payload_right[2] & 1<<6) ? 1:0) << 2 |
        //                      ((data_payload_right[2] & 1<<5) ? 1:0) << 3;
        //
        //     data_buffer[9] = ((data_payload_right[2] & 1<<4) ? 1:0) << 0 |
        //                      ((data_payload_right[2] & 1<<3) ? 1:0) << 1 |
        //                      ((data_payload_right[2] & 1<<2) ? 1:0) << 2 |
        //                      ((data_payload_right[2] & 1<<1) ? 1:0) << 3;
        // }

        // checking for a poll request from QMK
        // if (app_uart_get(&c) == NRF_SUCCESS && c == 's')
        // {
            // sending data to QMK, and an end byte
            // nrf_drv_uart_tx(data_buffer,10);
            // app_uart_put(0xE0);

            // debugging help, for printing keystates to a serial console
            /*
            for (uint8_t i = 0; i < 10; i++)
            {
                app_uart_put(data_buffer[i]);
            }
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
        // }
        // allowing UART buffers to clear
        // if (crypto_state == new_key_payload_ready)
        // nrf_delay_us(10);

        // // if no packets recieved from keyboards in a few seconds, assume either
        // // out of range, or sleeping due to no keys pressed, update keystates to off
        // left_active++;
        // right_active++;
        // if (left_active > INACTIVE)
        // {
        //     data_buffer[0] = 0;
        //     data_buffer[2] = 0;
        //     data_buffer[4] = 0;
        //     data_buffer[6] = 0;
        //     data_buffer[8] = 0;
        //     left_active = 0;
        // }
        // if (right_active > INACTIVE)
        // {
        //     data_buffer[1] = 0;
        //     data_buffer[3] = 0;
        //     data_buffer[5] = 0;
        //     data_buffer[7] = 0;
        //     data_buffer[9] = 0;
        //     right_active = 0;
        // }

        switch(crypto_state)
        {
            case key_not_ready:
                // Check if a random value is needed and if the RNG is ready and consume it.
                if (seed_index < sizeof(seed) && NRF_RNG->EVENTS_VALRDY)
                {
                    seed[seed_index++] = NRF_RNG->VALUE;
                    NRF_RNG->EVENTS_VALRDY = 0;
                    NRF_RNG->TASKS_START = 1;
                    if (seed_index == sizeof(seed))
                    {
                        memcpy(ack_payload.seed, seed, sizeof(ack_payload));
                        seed_index = 0;
                        crypto_state = seed_ready;
                        new_left_key_id = left_key_id + 1;
                        if (new_left_key_id == 0)
                        {
                            // Key id 0 is special (it's the initial key), so skip it.
                            new_left_key_id = 1;
                        }
                    }
                }
                break;
            case seed_ready:
                if (!decrypting)
                {
                    decrypting = true;
                    if (mitosis_crypto_rekey(&left_crypto[(new_left_key_id & 0x1) + 1], left_keyboard_crypto_key, ack_payload.seed, sizeof(ack_payload.seed)))
                    {
                        crypto_state = new_key_ready;
                    }
                    decrypting = false;
                }
                break;
            case new_key_ready:
                if (!decrypting)
                {
                    decrypting = true;
                    receiver_crypto.encrypt.ctr.iv.counter = ack_payload.key_id = new_left_key_id;
                    if (mitosis_aes_ctr_encrypt(&receiver_crypto.encrypt, sizeof(ack_payload.seed), ack_payload.seed, ack_payload.seed) &&
                        mitosis_cmac_compute(&receiver_crypto.cmac, ack_payload.payload, sizeof(ack_payload.payload), ack_payload.mac))
                    {
                        crypto_state = new_key_payload_ready;
                    }
                    decrypting = false;
                }
                break;
            default:
                break;
        }
        // This flip/flops between next key generation for the left and right halves.
        process_left = !process_left;
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
    uint8_t mac_scratch[MITOSIS_CMAC_OUTPUT_SIZE];
    uint32_t payload_length = sizeof(payload);
    uint32_t ack_payload_length = 0;

    if (pipe == 0)
    {
        // Pop packet and write payload to temp storage for verification.
        nrf_gzll_fetch_packet_from_rx_fifo(pipe, (uint8_t*) &payload, &payload_length);
        // If a crypto operation is in-progress, just ack the payload and continue.
        // This could cause missing keypresses, so consider queueing the payload
        // and process it as soon as this is complete.
        if (!decrypting)
        {
            decrypting = true;
            uint8_t index = (payload.key_id == 0) ? 0 : (payload.key_id & 0x1) + 1;
            mitosis_cmac_compute(&left_crypto[index].cmac, payload.payload, sizeof(payload.payload), mac_scratch);
            if (memcmp(payload.mac, mac_scratch, sizeof(payload.mac)) == 0)
            {
                // This is a valid message from the left keyboard; decrypt it.
                left_crypto[index].encrypt.ctr.iv.counter = payload.counter;
                if (mitosis_aes_ctr_decrypt(&left_crypto[index].encrypt, sizeof(payload.data), payload.data, data_payload_left))
                {
                    packet_received_left = true;
                    left_active = 0;
                    if (new_left_key_id != left_key_id && new_left_key_id == payload.key_id)
                    {
                        left_key_id_confirmed = true;
                        left_key_id = new_left_key_id;
                        // On confirmation, generate new key
                        crypto_state = key_not_ready;
                    }
                    if ((payload.key_id == 0 || payload.counter > 100) && left_key_id_confirmed && crypto_state == new_key_payload_ready)
                    {
                        ack_payload_length = sizeof(ack_payload);
                    }
                }
                else
                {
                    ++left_decrypt_fail;
                }
            }
            else
            {
                ++left_cmac_fail;
                if (crypto_state == new_key_payload_ready)
                {
                    // re-send the existing seed in case the keyboard reset and forgot.
                    ack_payload_length = sizeof(ack_payload);
                }
            }
            decrypting = false;
        }
        else
        {
            ++decrypt_collisions;
        }
    }
    else if (pipe == 1)
    {
        // Pop packet and write payload to temp storage for verification.
        nrf_gzll_fetch_packet_from_rx_fifo(pipe, (uint8_t*) &payload, &payload_length);
        // If a crypto operation is in-progress, just ack the payload and continue.
        // This could cause missing keypresses, so consider queueing the payload
        // and process it as soon as this is complete.
        if (!decrypting)
        {
            decrypting = true;
            mitosis_cmac_compute(&right_crypto.cmac, payload.payload, sizeof(payload.payload), mac_scratch);
            if (memcmp(payload.mac, mac_scratch, sizeof(payload.mac)) == 0)
            {
                // Valid message from the right keyboard; decrypt it.
                right_crypto.encrypt.ctr.iv.counter = payload.counter;
                if (mitosis_aes_ctr_decrypt(&right_crypto.encrypt, sizeof(payload.data), payload.data, data_payload_right))
                {
                    packet_received_right = true;
                    right_active = 0;
                }
                else
                {
                    ++right_decrypt_fail;
                }
            }
            else
            {
                ++right_cmac_fail;
            }
            decrypting = false;
        }
        else
        {
            ++decrypt_collisions;
        }
    }

    // not sure if required, I guess if enough packets are missed during blocking uart
    nrf_gzll_flush_rx_fifo(pipe);

    //load ACK payload into TX queue
    nrf_gzll_add_packet_to_tx_fifo(pipe, (uint8_t*) &ack_payload, ack_payload_length);
}
