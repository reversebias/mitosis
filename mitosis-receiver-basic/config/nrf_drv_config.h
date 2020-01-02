/* Copyright (c) 2015 Nordic Semiconductor. All Rights Reserved.
 *
 * The information contained herein is property of Nordic Semiconductor ASA.
 * Terms and conditions of usage are described in detail in NORDIC
 * SEMICONDUCTOR STANDARD SOFTWARE LICENSE AGREEMENT.
 *
 * Licensees are granted free, non-transferable use of the information. NO
 * WARRANTY of ANY KIND is provided. This heading must NOT be removed from
 * the file.
 *
 */

#ifndef NRF_DRV_CONFIG_H
#define NRF_DRV_CONFIG_H

/**
 * Provide a non-zero value here in applications that need to use several
 * peripherals with the same ID that are sharing certain resources
 * (for example, SPI0 and TWI0). Obviously, such peripherals cannot be used
 * simultaneously. Therefore, this definition allows to initialize the driver
 * for another peripheral from a given group only after the previously used one
 * is uninitialized. Normally, this is not possible, because interrupt handlers
 * are implemented in individual drivers.
 * This functionality requires a more complicated interrupt handling and driver
 * initialization, hence it is not always desirable to use it.
 */
#define PERIPHERAL_RESOURCE_SHARING_ENABLED  0

/* CLOCK */
#define CLOCK_ENABLED 0

#if (CLOCK_ENABLED == 1)
#define CLOCK_CONFIG_XTAL_FREQ          NRF_CLOCK_XTALFREQ_Default
#define CLOCK_CONFIG_LF_SRC             NRF_CLOCK_LFCLK_Xtal
#define CLOCK_CONFIG_IRQ_PRIORITY       APP_IRQ_PRIORITY_LOW
#endif

/* GPIOTE */
#define GPIOTE_ENABLED 0

#if (GPIOTE_ENABLED == 1)
#define GPIOTE_CONFIG_USE_SWI_EGU false
#define GPIOTE_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW
#define GPIOTE_CONFIG_NUM_OF_LOW_POWER_EVENTS 1
#endif

/* TIMER */
#define TIMER0_ENABLED 0

#if (TIMER0_ENABLED == 1)
#define TIMER0_CONFIG_FREQUENCY    NRF_TIMER_FREQ_16MHz
#define TIMER0_CONFIG_MODE         TIMER_MODE_MODE_Timer
#define TIMER0_CONFIG_BIT_WIDTH    TIMER_BITMODE_BITMODE_32Bit
#define TIMER0_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW

#define TIMER0_INSTANCE_INDEX      0
#endif

#define TIMER1_ENABLED 0

#if (TIMER1_ENABLED == 1)
#define TIMER1_CONFIG_FREQUENCY    NRF_TIMER_FREQ_16MHz
#define TIMER1_CONFIG_MODE         TIMER_MODE_MODE_Timer
#define TIMER1_CONFIG_BIT_WIDTH    TIMER_BITMODE_BITMODE_16Bit
#define TIMER1_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW

#define TIMER1_INSTANCE_INDEX      (TIMER0_ENABLED)
#endif

#define TIMER2_ENABLED 0

#if (TIMER2_ENABLED == 1)
#define TIMER2_CONFIG_FREQUENCY    NRF_TIMER_FREQ_16MHz
#define TIMER2_CONFIG_MODE         TIMER_MODE_MODE_Timer
#define TIMER2_CONFIG_BIT_WIDTH    TIMER_BITMODE_BITMODE_16Bit
#define TIMER2_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW

#define TIMER2_INSTANCE_INDEX      (TIMER1_ENABLED+TIMER0_ENABLED)
#endif

#define TIMER3_ENABLED 0

#if (TIMER3_ENABLED == 1)
#define TIMER3_CONFIG_FREQUENCY    NRF_TIMER_FREQ_16MHz
#define TIMER3_CONFIG_MODE         TIMER_MODE_MODE_Timer
#define TIMER3_CONFIG_BIT_WIDTH    TIMER_BITMODE_BITMODE_16Bit
#define TIMER3_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW

#define TIMER3_INSTANCE_INDEX      (TIMER2_ENABLED+TIMER1_ENABLED+TIMER0_ENABLED)
#endif

#define TIMER4_ENABLED 0

#if (TIMER4_ENABLED == 1)
#define TIMER4_CONFIG_FREQUENCY    NRF_TIMER_FREQ_16MHz
#define TIMER4_CONFIG_MODE         TIMER_MODE_MODE_Timer
#define TIMER4_CONFIG_BIT_WIDTH    TIMER_BITMODE_BITMODE_16Bit
#define TIMER4_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW

#define TIMER4_INSTANCE_INDEX      (TIMER3_ENABLED+TIMER2_ENABLED+TIMER1_ENABLED+TIMER0_ENABLED)
#endif


#define TIMER_COUNT (TIMER0_ENABLED + TIMER1_ENABLED + TIMER2_ENABLED + TIMER3_ENABLED + TIMER4_ENABLED)

/* RTC */
#define RTC0_ENABLED 0

#if (RTC0_ENABLED == 1)
#define RTC0_CONFIG_FREQUENCY    32678
#define RTC0_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW
#define RTC0_CONFIG_RELIABLE     false

#define RTC0_INSTANCE_INDEX      0
#endif

#define RTC1_ENABLED 0

#if (RTC1_ENABLED == 1)
#define RTC1_CONFIG_FREQUENCY    32768
#define RTC1_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW
#define RTC1_CONFIG_RELIABLE     false

#define RTC1_INSTANCE_INDEX      (RTC0_ENABLED)
#endif

#define RTC2_ENABLED 0

#if (RTC2_ENABLED == 1)
#define RTC2_CONFIG_FREQUENCY    32768
#define RTC2_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW
#define RTC2_CONFIG_RELIABLE     false

#define RTC2_INSTANCE_INDEX      (RTC0_ENABLED+RTC1_ENABLED)
#endif


#define RTC_COUNT                (RTC0_ENABLED+RTC1_ENABLED+RTC2_ENABLED)

#define NRF_MAXIMUM_LATENCY_US 2000

/* RNG */
#define RNG_ENABLED 0

#if (RNG_ENABLED == 1)
#define RNG_CONFIG_ERROR_CORRECTION true
#define RNG_CONFIG_POOL_SIZE        8
#define RNG_CONFIG_IRQ_PRIORITY     APP_IRQ_PRIORITY_LOW
#endif

/* PWM */

#define PWM0_ENABLED 0

#if (PWM0_ENABLED == 1)
#define PWM0_CONFIG_OUT0_PIN        2
#define PWM0_CONFIG_OUT1_PIN        3
#define PWM0_CONFIG_OUT2_PIN        4
#define PWM0_CONFIG_OUT3_PIN        5
#define PWM0_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW
#define PWM0_CONFIG_BASE_CLOCK      NRF_PWM_CLK_1MHz
#define PWM0_CONFIG_COUNT_MODE      NRF_PWM_MODE_UP
#define PWM0_CONFIG_TOP_VALUE       1000
#define PWM0_CONFIG_LOAD_MODE       NRF_PWM_LOAD_COMMON
#define PWM0_CONFIG_STEP_MODE       NRF_PWM_STEP_AUTO

#define PWM0_INSTANCE_INDEX 0
#endif

#define PWM1_ENABLED 0

#if (PWM1_ENABLED == 1)
#define PWM1_CONFIG_OUT0_PIN        2
#define PWM1_CONFIG_OUT1_PIN        3
#define PWM1_CONFIG_OUT2_PIN        4
#define PWM1_CONFIG_OUT3_PIN        5
#define PWM1_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW
#define PWM1_CONFIG_BASE_CLOCK      NRF_PWM_CLK_1MHz
#define PWM1_CONFIG_COUNT_MODE      NRF_PWM_MODE_UP
#define PWM1_CONFIG_TOP_VALUE       1000
#define PWM1_CONFIG_LOAD_MODE       NRF_PWM_LOAD_COMMON
#define PWM1_CONFIG_STEP_MODE       NRF_PWM_STEP_AUTO

#define PWM1_INSTANCE_INDEX (PWM0_ENABLED)
#endif

#define PWM2_ENABLED 0

#if (PWM2_ENABLED == 1)
#define PWM2_CONFIG_OUT0_PIN        2
#define PWM2_CONFIG_OUT1_PIN        3
#define PWM2_CONFIG_OUT2_PIN        4
#define PWM2_CONFIG_OUT3_PIN        5
#define PWM2_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW
#define PWM2_CONFIG_BASE_CLOCK      NRF_PWM_CLK_1MHz
#define PWM2_CONFIG_COUNT_MODE      NRF_PWM_MODE_UP
#define PWM2_CONFIG_TOP_VALUE       1000
#define PWM2_CONFIG_LOAD_MODE       NRF_PWM_LOAD_COMMON
#define PWM2_CONFIG_STEP_MODE       NRF_PWM_STEP_AUTO

#define PWM2_INSTANCE_INDEX (PWM0_ENABLED + PWM1_ENABLED)
#endif

#define PWM_COUNT   (PWM0_ENABLED + PWM1_ENABLED + PWM2_ENABLED)

/* SPI */
#define SPI0_ENABLED 0

#if (SPI0_ENABLED == 1)
#define SPI0_USE_EASY_DMA 0

#define SPI0_CONFIG_SCK_PIN         2
#define SPI0_CONFIG_MOSI_PIN        3
#define SPI0_CONFIG_MISO_PIN        4
#define SPI0_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW

#define SPI0_INSTANCE_INDEX 0
#endif

#define SPI1_ENABLED 0

#if (SPI1_ENABLED == 1)
#define SPI1_USE_EASY_DMA 0

#define SPI1_CONFIG_SCK_PIN         2
#define SPI1_CONFIG_MOSI_PIN        3
#define SPI1_CONFIG_MISO_PIN        4
#define SPI1_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW

#define SPI1_INSTANCE_INDEX (SPI0_ENABLED)
#endif

#define SPI2_ENABLED 0

#if (SPI2_ENABLED == 1)
#define SPI2_USE_EASY_DMA 0

#define SPI2_CONFIG_SCK_PIN         2
#define SPI2_CONFIG_MOSI_PIN        3
#define SPI2_CONFIG_MISO_PIN        4
#define SPI2_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW

#define SPI2_INSTANCE_INDEX (SPI0_ENABLED + SPI1_ENABLED)
#endif

#define SPI_COUNT   (SPI0_ENABLED + SPI1_ENABLED + SPI2_ENABLED)

/* SPIS */
#define SPIS0_ENABLED 0

#if (SPIS0_ENABLED == 1)
#define SPIS0_CONFIG_SCK_PIN         2
#define SPIS0_CONFIG_MOSI_PIN        3
#define SPIS0_CONFIG_MISO_PIN        4
#define SPIS0_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW

#define SPIS0_INSTANCE_INDEX 0
#endif

#define SPIS1_ENABLED 0

#if (SPIS1_ENABLED == 1)
#define SPIS1_CONFIG_SCK_PIN         2
#define SPIS1_CONFIG_MOSI_PIN        3
#define SPIS1_CONFIG_MISO_PIN        4
#define SPIS1_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW

#define SPIS1_INSTANCE_INDEX SPIS0_ENABLED
#endif

#define SPIS2_ENABLED 0

#if (SPIS2_ENABLED == 1)
#define SPIS2_CONFIG_SCK_PIN         2
#define SPIS2_CONFIG_MOSI_PIN        3
#define SPIS2_CONFIG_MISO_PIN        4
#define SPIS2_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW

#define SPIS2_INSTANCE_INDEX (SPIS0_ENABLED + SPIS1_ENABLED)
#endif

#define SPIS_COUNT   (SPIS0_ENABLED + SPIS1_ENABLED + SPIS2_ENABLED)

/* UART */
#define UART0_ENABLED 1

#if (UART0_ENABLED == 1)
#define UART0_CONFIG_HWFC         NRF_UART_HWFC_DISABLED
#define UART0_CONFIG_PARITY       NRF_UART_PARITY_EXCLUDED
#define UART0_CONFIG_BAUDRATE     NRF_UART_BAUDRATE_115200
#define UART0_CONFIG_PSEL_TXD 9
#define UART0_CONFIG_PSEL_RXD 11
#define UART0_CONFIG_PSEL_CTS 10
#define UART0_CONFIG_PSEL_RTS 8
#define UART0_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW
#ifdef NRF52
#define UART0_CONFIG_USE_EASY_DMA false
//Compile time flag
#define UART_EASY_DMA_SUPPORT     1
#define UART_LEGACY_SUPPORT       1
#endif //NRF52
#endif

#define TWI0_ENABLED 0

#if (TWI0_ENABLED == 1)
#define TWI0_USE_EASY_DMA 0

#define TWI0_CONFIG_FREQUENCY    NRF_TWI_FREQ_100K
#define TWI0_CONFIG_SCL          0
#define TWI0_CONFIG_SDA          1
#define TWI0_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW

#define TWI0_INSTANCE_INDEX      0
#endif

#define TWI1_ENABLED 0

#if (TWI1_ENABLED == 1)
#define TWI1_USE_EASY_DMA 0

#define TWI1_CONFIG_FREQUENCY    NRF_TWI_FREQ_100K
#define TWI1_CONFIG_SCL          0
#define TWI1_CONFIG_SDA          1
#define TWI1_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW

#define TWI1_INSTANCE_INDEX      (TWI0_ENABLED)
#endif

#define TWI_COUNT                (TWI0_ENABLED + TWI1_ENABLED)

/* TWIS */
#define TWIS0_ENABLED 0

#if (TWIS0_ENABLED == 1)
    #define TWIS0_CONFIG_ADDR0        0
    #define TWIS0_CONFIG_ADDR1        0 /* 0: Disabled */
    #define TWIS0_CONFIG_SCL          0
    #define TWIS0_CONFIG_SDA          1
    #define TWIS0_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW

    #define TWIS0_INSTANCE_INDEX      0
#endif

#define TWIS1_ENABLED 0

#if (TWIS1_ENABLED ==  1)
    #define TWIS1_CONFIG_ADDR0        0
    #define TWIS1_CONFIG_ADDR1        0 /* 0: Disabled */
    #define TWIS1_CONFIG_SCL          0
    #define TWIS1_CONFIG_SDA          1
    #define TWIS1_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW

    #define TWIS1_INSTANCE_INDEX      (TWIS0_ENABLED)
#endif

#define TWIS_COUNT (TWIS0_ENABLED + TWIS1_ENABLED)
/* For more documentation see nrf_drv_twis.h file */
#define TWIS_ASSUME_INIT_AFTER_RESET_ONLY 0
/* For more documentation see nrf_drv_twis.h file */
#define TWIS_NO_SYNC_MODE 0

/* QDEC */
#define QDEC_ENABLED 0

#if (QDEC_ENABLED == 1)
#define QDEC_CONFIG_REPORTPER    NRF_QDEC_REPORTPER_10
#define QDEC_CONFIG_SAMPLEPER    NRF_QDEC_SAMPLEPER_16384us
#define QDEC_CONFIG_PIO_A        1
#define QDEC_CONFIG_PIO_B        2
#define QDEC_CONFIG_PIO_LED      3
#define QDEC_CONFIG_LEDPRE       511
#define QDEC_CONFIG_LEDPOL       NRF_QDEC_LEPOL_ACTIVE_HIGH
#define QDEC_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW
#define QDEC_CONFIG_DBFEN        false
#define QDEC_CONFIG_SAMPLE_INTEN false
#endif

/* ADC */
#define ADC_ENABLED 0

#if (ADC_ENABLED == 1)
#define ADC_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW
#endif


/* SAADC */
#define SAADC_ENABLED 0

#if (SAADC_ENABLED == 1)
#define SAADC_CONFIG_RESOLUTION      NRF_SAADC_RESOLUTION_10BIT
#define SAADC_CONFIG_OVERSAMPLE      NRF_SAADC_OVERSAMPLE_DISABLED
#define SAADC_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW
#endif

/* PDM */
#define PDM_ENABLED 0

#if (PDM_ENABLED == 1)
#define PDM_CONFIG_MODE            NRF_PDM_MODE_MONO
#define PDM_CONFIG_EDGE            NRF_PDM_EDGE_LEFTFALLING
#define PDM_CONFIG_CLOCK_FREQ      NRF_PDM_FREQ_1032K
#define PDM_CONFIG_IRQ_PRIORITY    APP_IRQ_PRIORITY_LOW
#endif

/* COMP */
#define COMP_ENABLED 0

#if (COMP_ENABLED == 1)
#define COMP_CONFIG_REF     		NRF_COMP_REF_Int1V8
#define COMP_CONFIG_MAIN_MODE		NRF_COMP_MAIN_MODE_SE
#define COMP_CONFIG_SPEED_MODE		NRF_COMP_SP_MODE_High
#define COMP_CONFIG_HYST			NRF_COMP_HYST_NoHyst
#define COMP_CONFIG_ISOURCE			NRF_COMP_ISOURCE_Off
#define COMP_CONFIG_IRQ_PRIORITY 	APP_IRQ_PRIORITY_LOW
#define COMP_CONFIG_INPUT        	NRF_COMP_INPUT_0
#endif

/* LPCOMP */
#define LPCOMP_ENABLED 0

#if (LPCOMP_ENABLED == 1)
#define LPCOMP_CONFIG_REFERENCE    NRF_LPCOMP_REF_SUPPLY_4_8
#define LPCOMP_CONFIG_DETECTION    NRF_LPCOMP_DETECT_DOWN
#define LPCOMP_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_LOW
#define LPCOMP_CONFIG_INPUT        NRF_LPCOMP_INPUT_0
#endif

/* WDT */
#define WDT_ENABLED 0

#if (WDT_ENABLED == 1)
#define WDT_CONFIG_BEHAVIOUR     NRF_WDT_BEHAVIOUR_RUN_SLEEP
#define WDT_CONFIG_RELOAD_VALUE  2000
#define WDT_CONFIG_IRQ_PRIORITY  APP_IRQ_PRIORITY_HIGH
#endif

/* SWI EGU */
#ifdef NRF52
    #define EGU_ENABLED 0
#endif

/* I2S */
#define I2S_ENABLED 0

#if (I2S_ENABLED == 1)
#define I2S_CONFIG_SCK_PIN      22
#define I2S_CONFIG_LRCK_PIN     23
#define I2S_CONFIG_MCK_PIN      NRF_DRV_I2S_PIN_NOT_USED
#define I2S_CONFIG_SDOUT_PIN    24
#define I2S_CONFIG_SDIN_PIN     25
#define I2S_CONFIG_IRQ_PRIORITY APP_IRQ_PRIORITY_HIGH
#define I2S_CONFIG_MASTER       NRF_I2S_MODE_MASTER
#define I2S_CONFIG_FORMAT       NRF_I2S_FORMAT_I2S
#define I2S_CONFIG_ALIGN        NRF_I2S_ALIGN_LEFT
#define I2S_CONFIG_SWIDTH       NRF_I2S_SWIDTH_16BIT
#define I2S_CONFIG_CHANNELS     NRF_I2S_CHANNELS_STEREO
#define I2S_CONFIG_MCK_SETUP    NRF_I2S_MCK_32MDIV8
#define I2S_CONFIG_RATIO        NRF_I2S_RATIO_256X
#endif

#include "nrf_drv_config_validation.h"

#endif // NRF_DRV_CONFIG_H
