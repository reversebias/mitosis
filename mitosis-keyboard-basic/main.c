
// #define COMPILE_RIGHT
#define COMPILE_LEFT

#include "mitosis.h"
#include "nrf_drv_config.h"
#include "nrf_gzll.h"
#include "nrf_gpio.h"
#include "nrf_delay.h"
#include "nrf_drv_clock.h"
#include "nrf_drv_rtc.h"
#include <string.h>
#include "mitosis-crypto.h"


/*****************************************************************************/
/** Configuration */
/*****************************************************************************/

const nrf_drv_rtc_t rtc_maint = NRF_DRV_RTC_INSTANCE(0); /**< Declaring an instance of nrf_drv_rtc for RTC0. */
const nrf_drv_rtc_t rtc_deb = NRF_DRV_RTC_INSTANCE(1); /**< Declaring an instance of nrf_drv_rtc for RTC1. */


// Define payload length
#define TX_PAYLOAD_LENGTH sizeof(mitosis_crypto_data_payload_t) ///< 24 byte payload length when transmitting

// Data and acknowledgement payloads
static mitosis_crypto_data_payload_t data_payload;  ///< Payload to send to Host.
static mitosis_crypto_seed_payload_t ack_payload;   ///< Payloads received in ACKs from Host.

// Crypto state
static mitosis_crypto_context_t crypto;
static mitosis_crypto_context_t receiver_crypto;
static volatile bool encrypting = false;

// Debounce time (dependent on tick frequency)
#define DEBOUNCE 5
#define ACTIVITY 500

// Key buffers
static uint32_t keys, keys_snapshot;
static uint32_t debounce_ticks, activity_ticks;
static volatile bool debouncing = false;

// Debug helper variables
static uint16_t max_rtx = 0;
static uint32_t rtx_count = 0;
static uint32_t tx_count = 0;
static uint32_t tx_fail = 0;
static volatile uint32_t encrypt_collisions = 0;
static volatile uint32_t encrypt_failure = 0;
static volatile uint32_t cmac_failure = 0;
static volatile uint32_t rekey_cmac_success = 0;
static volatile uint32_t rekey_cmac_failure = 0;
static volatile uint32_t rekey_decrypt_failure = 0;

// Setup switch pins with pullups
static void gpio_config(void)
{
    nrf_gpio_cfg_sense_input(S01, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S02, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S03, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S04, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S05, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S06, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S07, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S08, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S09, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S10, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S11, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S12, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S13, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S14, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S15, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S16, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S17, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S18, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S19, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S20, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S21, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S22, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
    nrf_gpio_cfg_sense_input(S23, NRF_GPIO_PIN_PULLUP, NRF_GPIO_PIN_SENSE_LOW);
}

// Return the key states, masked with valid key pins
static uint32_t read_keys(void)
{
    return ~NRF_GPIO->IN & INPUT_MASK;
}

// Assemble packet and send to receiver
static void send_data(void)
{
    // If an encryption operation is already in-progress, skip reading the keys
    // and just return.
    // This could cause missing keypresses so consider queueing the work to be
    // done once the crypto operation is done.
    if (!encrypting)
    {
        encrypting = true;
        uint8_t* data = data_payload.data;
        data[0] = ((keys & 1<<S01) ? 1:0) << 7 | \
                  ((keys & 1<<S02) ? 1:0) << 6 | \
                  ((keys & 1<<S03) ? 1:0) << 5 | \
                  ((keys & 1<<S04) ? 1:0) << 4 | \
                  ((keys & 1<<S05) ? 1:0) << 3 | \
                  ((keys & 1<<S06) ? 1:0) << 2 | \
                  ((keys & 1<<S07) ? 1:0) << 1 | \
                  ((keys & 1<<S08) ? 1:0) << 0;

        data[1] = ((keys & 1<<S09) ? 1:0) << 7 | \
                  ((keys & 1<<S10) ? 1:0) << 6 | \
                  ((keys & 1<<S11) ? 1:0) << 5 | \
                  ((keys & 1<<S12) ? 1:0) << 4 | \
                  ((keys & 1<<S13) ? 1:0) << 3 | \
                  ((keys & 1<<S14) ? 1:0) << 2 | \
                  ((keys & 1<<S15) ? 1:0) << 1 | \
                  ((keys & 1<<S16) ? 1:0) << 0;

        data[2] = ((keys & 1<<S17) ? 1:0) << 7 | \
                  ((keys & 1<<S18) ? 1:0) << 6 | \
                  ((keys & 1<<S19) ? 1:0) << 5 | \
                  ((keys & 1<<S20) ? 1:0) << 4 | \
                  ((keys & 1<<S21) ? 1:0) << 3 | \
                  ((keys & 1<<S22) ? 1:0) << 2 | \
                  ((keys & 1<<S23) ? 1:0) << 1 | \
                  0 << 0;

        if (mitosis_aes_ctr_encrypt(&crypto.encrypt, sizeof(data_payload.data), data_payload.data, data_payload.data))
        {
            // Copy the used counter and increment at the same time.
            data_payload.counter = crypto.encrypt.ctr.iv.counter++;
            // compute cmac on data and counter.
            if (mitosis_cmac_compute(&crypto.cmac, data_payload.payload, sizeof(data_payload.payload), data_payload.mac))
            {
                if (nrf_gzll_add_packet_to_tx_fifo(PIPE_NUMBER, (uint8_t*) &data_payload, TX_PAYLOAD_LENGTH))
                {
                    ++tx_count;
                }
                else
                {
                    ++tx_fail;
                }
            }
            else
            {
                ++cmac_failure;
            }
        }
        else
        {
            ++encrypt_failure;
        }
        encrypting = false;
    }
    else
    {
        ++encrypt_collisions;
    }
}

// 8Hz held key maintenance, keeping the reciever keystates valid
static void handler_maintenance(nrf_drv_rtc_int_type_t int_type)
{
    send_data();
}

// 1000Hz debounce sampling
static void handler_debounce(nrf_drv_rtc_int_type_t int_type)
{
    // debouncing, waits until there have been no transitions in 5ms (assuming five 1ms ticks)
    if (debouncing)
    {
        // if debouncing, check if current keystates equal to the snapshot
        if (keys_snapshot == read_keys())
        {
            // DEBOUNCE ticks of stable sampling needed before sending data
            debounce_ticks++;
            if (debounce_ticks == DEBOUNCE)
            {
                keys = keys_snapshot;
                send_data();
            }
        }
        else
        {
            // if keys change, start period again
            debouncing = false;
        }
    }
    else
    {
        // if the keystate is different from the last data
        // sent to the receiver, start debouncing
        if (keys != read_keys())
        {
            keys_snapshot = read_keys();
            debouncing = true;
            debounce_ticks = 0;
        }
    }

    // looking for 500 ticks of no keys pressed, to go back to deep sleep
    if (read_keys() == 0)
    {
        activity_ticks++;
        if (activity_ticks > ACTIVITY)
        {
            nrf_drv_rtc_disable(&rtc_maint);
            nrf_drv_rtc_disable(&rtc_deb);
        }
    }
    else
    {
        activity_ticks = 0;
    }

}


// Low frequency clock configuration
static void lfclk_config(void)
{
    nrf_drv_clock_init();

    nrf_drv_clock_lfclk_request(NULL);
}

// RTC peripheral configuration
static void rtc_config(void)
{
    //Initialize RTC instance
    nrf_drv_rtc_init(&rtc_maint, NULL, handler_maintenance);
    nrf_drv_rtc_init(&rtc_deb, NULL, handler_debounce);

    //Enable tick event & interrupt
    nrf_drv_rtc_tick_enable(&rtc_maint,true);
    nrf_drv_rtc_tick_enable(&rtc_deb,true);

    //Power on RTC instance
    //nrf_drv_rtc_enable(&rtc_maint);
    //nrf_drv_rtc_enable(&rtc_deb);
}

int main()
{
    // Initialize Gazell
    nrf_gzll_init(NRF_GZLL_MODE_DEVICE);

    // Attempt sending every packet up to 100 times
    nrf_gzll_set_max_tx_attempts(100);

    // Addressing
    nrf_gzll_set_base_address_0(0x01020304);
    nrf_gzll_set_base_address_1(0x05060708);

    // Enable Gazell to start sending over the air
    nrf_gzll_enable();

    // Configure 32kHz xtal oscillator
    lfclk_config();

    // Configure RTC peripherals with ticks
    rtc_config();

    // Configure all keys as inputs with pullups
    gpio_config();

    // Set the GPIOTE PORT event as interrupt source, and enable interrupts for GPIOTE
    NRF_GPIOTE->INTENSET = GPIOTE_INTENSET_PORT_Msk;
    NVIC_EnableIRQ(GPIOTE_IRQn);

#ifdef COMPILE_LEFT
    mitosis_crypto_init(&crypto, left_keyboard_crypto_key);
#elif defined(COMPILE_RIGHT)
    mitosis_crypto_init(&crypto, right_keyboard_crypto_key);
#else
    #error "no keyboard half specified"
#endif
    mitosis_crypto_init(&receiver_crypto, receiver_crypto_key);


    // Main loop, constantly sleep, waiting for RTC and gpio IRQs
    while(1)
    {
        __SEV();
        __WFE();
        __WFE();
    }
}

// This handler will be run after wakeup from system ON (GPIO wakeup)
void GPIOTE_IRQHandler(void)
{
    if(NRF_GPIOTE->EVENTS_PORT)
    {
        //clear wakeup event
        NRF_GPIOTE->EVENTS_PORT = 0;

        //enable rtc interupt triggers
        nrf_drv_rtc_enable(&rtc_maint);
        nrf_drv_rtc_enable(&rtc_deb);

        debouncing = false;
        debounce_ticks = 0;
        activity_ticks = 0;
    }
}



/*****************************************************************************/
/** Gazell callback function definitions  */
/*****************************************************************************/

void  nrf_gzll_device_tx_success(uint32_t pipe, nrf_gzll_device_tx_info_t tx_info)
{
    uint32_t ack_payload_length = sizeof(ack_payload);
    uint8_t mac_scratch[MITOSIS_CMAC_OUTPUT_SIZE];

    if (pipe != PIPE_NUMBER)
    {
        // Ignore responses from the wrong pipe (shouldn't happen).
        return;
    }

    if (tx_info.payload_received_in_ack)
    {
        // If the receiver sent back payload, it's a new seed for encryption keys.
        // Collect this packet and validate.
        nrf_gzll_fetch_packet_from_rx_fifo(pipe, (uint8_t*) &ack_payload, &ack_payload_length);
        mitosis_cmac_compute(&receiver_crypto.cmac, ack_payload.payload, sizeof(ack_payload.payload), mac_scratch);
        if (memcmp(mac_scratch, ack_payload.mac, sizeof(mac_scratch)) == 0)
        {
            ++rekey_cmac_success;
            receiver_crypto.encrypt.ctr.iv.counter = ack_payload.key_id;
            if (mitosis_aes_ctr_decrypt(&receiver_crypto.encrypt, sizeof(ack_payload.seed), ack_payload.seed, mac_scratch))
            {
                // The seed packet validates! update the encryption keys.
                data_payload.key_id = ack_payload.key_id;

                #ifdef COMPILE_LEFT
                mitosis_crypto_rekey(&crypto, left_keyboard_crypto_key, mac_scratch, sizeof(ack_payload.seed));
                #elif defined(COMPILE_RIGHT)
                mitosis_crypto_rekey(&crypto, right_keyboard_crypto_key, mac_scratch, sizeof(ack_payload.seed));
                #endif
            }
            else
            {
                ++rekey_decrypt_failure;
            }
        }
        else
        {
            ++rekey_cmac_failure;
        }
    }
    if (tx_info.num_tx_attempts > max_rtx)
    {
        max_rtx = tx_info.num_tx_attempts;
    }
    rtx_count += tx_info.num_tx_attempts;
}

// no action is taken when a packet fails to send, this might need to change
void nrf_gzll_device_tx_failed(uint32_t pipe, nrf_gzll_device_tx_info_t tx_info)
{

}

// Callbacks not needed
void nrf_gzll_host_rx_data_ready(uint32_t pipe, nrf_gzll_host_rx_info_t rx_info)
{}
void nrf_gzll_disabled()
{}
