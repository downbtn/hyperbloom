/**
 * @file    gpio.h
 * @brief   General-Purpose Input/Output (GPIO) function prototypes and data types.
 */

/******************************************************************************
 *
 * Copyright (C) 2024 Analog Devices, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************************/

/* Define to prevent redundant inclusion */
#ifndef LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX32657_GPIO_H_
#define LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX32657_GPIO_H_

/* **** Includes **** */
#include "gpio_regs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup gpio General-Purpose Input/Output (GPIO)
 * @ingroup periphlibs
 * @{
 */

/* **** Definitions **** */
/**
 * @defgroup gpio_port_pin Port and Pin Definitions
 * @ingroup gpio
 * @{
 * @defgroup gpio_port Port Definitions
 * @ingroup gpio_port_pin
 * @{
 */
#define MXC_GPIO_PORT_0 ((uint32_t)(1UL << 0)) /**< Port 0  Define*/
#define MXC_GPIO_PORT_1 ((uint32_t)(1UL << 1)) /**< Port 1  Define*/
#define MXC_GPIO_PORT_2 ((uint32_t)(1UL << 2)) /**< Port 2  Define*/
#define MXC_GPIO_PORT_3 ((uint32_t)(1UL << 3)) /**< Port 3  Define*/
/**@} end of gpio_port group*/
/**
 * @defgroup gpio_pin Pin Definitions
 * @ingroup gpio_port_pin
 * @{
 */
#define MXC_GPIO_PIN_0 ((uint32_t)(1UL << 0)) /**< Pin 0 Define */
#define MXC_GPIO_PIN_1 ((uint32_t)(1UL << 1)) /**< Pin 1 Define */
#define MXC_GPIO_PIN_2 ((uint32_t)(1UL << 2)) /**< Pin 2 Define */
#define MXC_GPIO_PIN_3 ((uint32_t)(1UL << 3)) /**< Pin 3 Define */
#define MXC_GPIO_PIN_4 ((uint32_t)(1UL << 4)) /**< Pin 4 Define */
#define MXC_GPIO_PIN_5 ((uint32_t)(1UL << 5)) /**< Pin 5 Define */
#define MXC_GPIO_PIN_6 ((uint32_t)(1UL << 6)) /**< Pin 6 Define */
#define MXC_GPIO_PIN_7 ((uint32_t)(1UL << 7)) /**< Pin 7 Define */
#define MXC_GPIO_PIN_8 ((uint32_t)(1UL << 8)) /**< Pin 8 Define */
#define MXC_GPIO_PIN_9 ((uint32_t)(1UL << 9)) /**< Pin 9 Define */
#define MXC_GPIO_PIN_10 ((uint32_t)(1UL << 10)) /**< Pin 10 Define */
#define MXC_GPIO_PIN_11 ((uint32_t)(1UL << 11)) /**< Pin 11 Define */
#define MXC_GPIO_PIN_12 ((uint32_t)(1UL << 12)) /**< Pin 12 Define */
#define MXC_GPIO_PIN_13 ((uint32_t)(1UL << 13)) /**< Pin 13 Define */
#define MXC_GPIO_PIN_14 ((uint32_t)(1UL << 14)) /**< Pin 14 Define */
#define MXC_GPIO_PIN_15 ((uint32_t)(1UL << 15)) /**< Pin 15 Define */
#define MXC_GPIO_PIN_16 ((uint32_t)(1UL << 16)) /**< Pin 16 Define */
#define MXC_GPIO_PIN_17 ((uint32_t)(1UL << 17)) /**< Pin 17 Define */
#define MXC_GPIO_PIN_18 ((uint32_t)(1UL << 18)) /**< Pin 18 Define */
#define MXC_GPIO_PIN_19 ((uint32_t)(1UL << 19)) /**< Pin 19 Define */
#define MXC_GPIO_PIN_20 ((uint32_t)(1UL << 20)) /**< Pin 20 Define */
#define MXC_GPIO_PIN_21 ((uint32_t)(1UL << 21)) /**< Pin 21 Define */
#define MXC_GPIO_PIN_22 ((uint32_t)(1UL << 22)) /**< Pin 22 Define */
#define MXC_GPIO_PIN_23 ((uint32_t)(1UL << 23)) /**< Pin 23 Define */
#define MXC_GPIO_PIN_24 ((uint32_t)(1UL << 24)) /**< Pin 24 Define */
#define MXC_GPIO_PIN_25 ((uint32_t)(1UL << 25)) /**< Pin 25 Define */
#define MXC_GPIO_PIN_26 ((uint32_t)(1UL << 26)) /**< Pin 26 Define */
#define MXC_GPIO_PIN_27 ((uint32_t)(1UL << 27)) /**< Pin 27 Define */
#define MXC_GPIO_PIN_28 ((uint32_t)(1UL << 28)) /**< Pin 28 Define */
#define MXC_GPIO_PIN_29 ((uint32_t)(1UL << 29)) /**< Pin 29 Define */
#define MXC_GPIO_PIN_30 ((uint32_t)(1UL << 30)) /**< Pin 30 Define */
#define MXC_GPIO_PIN_31 ((uint32_t)(1UL << 31)) /**< Pin 31 Define */
/**@} end of gpio_pin group */
/**@} end of gpio_port_pin group */

/**
 * @brief      Type alias for a GPIO callback function with prototype:
 * @code
    void callback_fn(void *cbdata);
 * @endcode
 * @param      cbdata  A void pointer to the data type as registered when
 *                     MXC_GPIO_RegisterCallback() was called.
 */
typedef void (*mxc_gpio_callback_fn)(void *cbdata);

/**
 * @brief   Enumeration type for the GPIO Function Type
 */
typedef enum {
    MXC_GPIO_FUNC_IN, /**< GPIO Input */
    MXC_GPIO_FUNC_OUT, /**< GPIO Output */
    MXC_GPIO_FUNC_ALT1, /**< Alternate Function Selection */
    MXC_GPIO_FUNC_ALT2, /**< Alternate Function Selection */
    MXC_GPIO_FUNC_ALT3, /**< Alternate Function Selection */
    MXC_GPIO_FUNC_ALT4, /**< Alternate Function Selection */
} mxc_gpio_func_t;

/**
 * @brief   Enumeration type for the voltage level on a given pin.
 */
typedef enum {
    MXC_GPIO_VSSEL_VDDIO, /**< Set pin to VIDDIO voltage */
    MXC_GPIO_VSSEL_VDDIOH, /**< Set pin to VIDDIOH voltage */
} mxc_gpio_vssel_t;

/**
 * @brief   Enumeration type for drive strength on a given pin.
 *          This represents what the two GPIO_DS[2] (Drive Strength) 
 *          registers are set to for a given GPIO pin; NOT the
 *          drive strength level.
 *
 *          For example:
 *              MXC_GPIO_DRVSTR_0: GPIO_DS1[pin] = 0; GPIO_DS0[pin] = 0
 *              MXC_GPIO_DRVSTR_1: GPIO_DS1[pin] = 0; GPIO_DS0[pin] = 1
 *              MXC_GPIO_DRVSTR_2: GPIO_DS1[pin] = 1; GPIO_DS0[pin] = 0
 *              MXC_GPIO_DRVSTR_3: GPIO_DS1[pin] = 1; GPIO_DS0[pin] = 1
 *
 *          Refer to the user guide and datasheet to select the
 *          appropriate drive strength. Note: the drive strength values
 *          are not linear, and can vary from pin-to-pin and the state
 *          of the GPIO pin (alternate function and voltage level).
 */
typedef enum {
    MXC_GPIO_DRVSTR_0, /**< Drive Strength GPIO_DS[2][pin]=0b00 */
    MXC_GPIO_DRVSTR_1, /**< Drive Strength GPIO_DS[2][pin]=0b01 */
    MXC_GPIO_DRVSTR_2, /**< Drive Strength GPIO_DS[2][pin]=0b10 */
    MXC_GPIO_DRVSTR_3, /**< Drive Strength GPIO_DS[2][pin]=0b11 */
} mxc_gpio_drvstr_t;

/**
 * @brief   Enumeration type for the type of GPIO pad on a given pin.
 */
typedef enum {
    MXC_GPIO_PAD_NONE, /**< No pull-up or pull-down */
    MXC_GPIO_PAD_PULL_UP, /**< Set pad to strong pull-up */
    MXC_GPIO_PAD_PULL_DOWN, /**< Set pad to strong pull-down */
    MXC_GPIO_PAD_WEAK_PULL_UP, /**< Set pad to weak pull-up */
    MXC_GPIO_PAD_WEAK_PULL_DOWN /**< Set pad to weak pull-down */
} mxc_gpio_pad_t;

/**
 * @brief   Structure type for configuring a GPIO port.
 */
typedef struct {
    mxc_gpio_regs_t *port; /**< Pointer to GPIO regs */
    uint32_t mask; /**< Pin mask (multiple pins may be set) */
    mxc_gpio_func_t func; /**< Function type */
    mxc_gpio_pad_t pad; /**< Pad type */
    mxc_gpio_vssel_t vssel; /**< Voltage select */
    mxc_gpio_drvstr_t drvstr; /**< Drive Strength select */
} mxc_gpio_cfg_t;

/**
 * @brief   Enumeration type for the interrupt modes.
 */
typedef enum {
    MXC_GPIO_INT_LEVEL, /**< Interrupt is level sensitive */
    MXC_GPIO_INT_EDGE /**< Interrupt is edge sensitive */
} mxc_gpio_int_mode_t;

/**
 * @brief   Enumeration type for the interrupt polarity.
 */
typedef enum {
    MXC_GPIO_INT_FALLING, /**< Interrupt triggers on falling edge */
    MXC_GPIO_INT_HIGH, /**< Interrupt triggers when level is high */
    MXC_GPIO_INT_RISING, /**< Interrupt triggers on rising edge */
    MXC_GPIO_INT_LOW, /**< Interrupt triggers when level is low */
    MXC_GPIO_INT_BOTH /**< Interrupt triggers on either edge */
} mxc_gpio_int_pol_t;

/**
 * @brief   Enumeration type for the pin configuration lock mechanism.
 */
typedef enum {
    MXC_GPIO_CONFIG_UNLOCKED = 0, /**< Allow changing pins' configuration. */
    MXC_GPIO_CONFIG_LOCKED, /**< Ignore changes to a pin's configuration. */
} mxc_gpio_config_lock_t;

/* **** Function Prototypes **** */

/**
 * @brief      Initialize GPIO.
 * @param      portMask     Mask for the port to be initialized
 * @return     #E_NO_ERROR if everything is successful.
 */
int MXC_GPIO_Init(uint32_t portMask);

/**
 * @brief      Shutdown GPIO.
 * @param      portMask     Mask for the port to be initialized
 * @return     #E_NO_ERROR if everything is successful.
 */
int MXC_GPIO_Shutdown(uint32_t portMask);

/**
 * @brief      Reset GPIO.
 * @param      portMask     Mask for the port to be initialized
 * @return     #E_NO_ERROR if everything is successful.
 */
int MXC_GPIO_Reset(uint32_t portMask);

/**
 * @brief      Configure GPIO pin(s).
 * @param      cfg   Pointer to configuration structure describing the pin.
 * @return     #E_NO_ERROR if everything is successful.
 */
int MXC_GPIO_Config(const mxc_gpio_cfg_t *cfg);

/**
 * @brief      Gets the pin(s) input state.
 * @param      port  Pointer to the GPIO port registers
 * @param      mask  Mask of the pin(s) to read
 * @return     The requested pin state.
 */
uint32_t MXC_GPIO_InGet(mxc_gpio_regs_t *port, uint32_t mask);

/**
 * @brief      Sets the pin(s) to a high level output.
 * @param      port  Pointer to the GPIO port registers
 * @param      mask  Mask of the pin(s) to set
 */
void MXC_GPIO_OutSet(mxc_gpio_regs_t *port, uint32_t mask);

/**
 * @brief      Clears the pin(s) to a low level output.
 * @param      port  Pointer to the GPIO port registers
 * @param      mask  Mask of the pin(s) to clear
 */
void MXC_GPIO_OutClr(mxc_gpio_regs_t *port, uint32_t mask);

/**
 * @brief      Gets the pin(s) output state.
 * @param      port  Pointer to the GPIO port registers
 * @param      mask  Mask of the pin(s) to read the output state of
 * @return     The state of the requested pin.
 *
 */
uint32_t MXC_GPIO_OutGet(mxc_gpio_regs_t *port, uint32_t mask);

/**
 * @brief      Write the pin(s) to a desired output level.
 * @param      port  Pointer to the GPIO port registers
 * @param      mask  Mask of the pin(s) to set output level of
 * @param      val   Desired output level of the pin(s). This will be masked
 *                   with the configuration mask.
 */
void MXC_GPIO_OutPut(mxc_gpio_regs_t *port, uint32_t mask, uint32_t val);

/**
 * @brief      Toggles the the pin(s) output level.
 * @param      port  Pointer to the GPIO port registers
 * @param      mask  Mask of the pin(s) to toggle the output
 */
void MXC_GPIO_OutToggle(mxc_gpio_regs_t *port, uint32_t mask);

/**
 * @brief      Configure GPIO interrupt(s)
 * @param      cfg   Pointer to configuration structure describing the pin.
 * @param      pol   Requested interrupt polarity.
 * @return     #E_NO_ERROR if everything is successful.
 */
int MXC_GPIO_IntConfig(const mxc_gpio_cfg_t *cfg, mxc_gpio_int_pol_t pol);

/**
 * @brief      Enables the specified GPIO interrupt
 * @param      port  Pointer to the GPIO port registers
 * @param      mask  Mask of the pin(s) to enable interrupts for
 * 
 */
void MXC_GPIO_EnableInt(mxc_gpio_regs_t *port, uint32_t mask);

/**
 * @brief      Disables the specified GPIO interrupt.
 * @param      port  Pointer to the GPIO port registers
 * @param      mask  Mask of the pin(s) to disable interrupts for
 */
void MXC_GPIO_DisableInt(mxc_gpio_regs_t *port, uint32_t mask);

/**
 * @brief      Gets the interrupt(s) status on a GPIO port
 *
 * @param      port  Pointer to the GPIO port registers
 *
 * @return     The requested interrupt status.
 */
uint32_t MXC_GPIO_GetFlags(mxc_gpio_regs_t *port);

/**
 * @brief      Gets the interrupt(s) status on a GPIO port
 *
 * @param      port  Pointer to the GPIO port registers
 * @param      flags  The flags to clear
 */
void MXC_GPIO_ClearFlags(mxc_gpio_regs_t *port, uint32_t flags);

/**
 * @brief      Registers a callback for the interrupt on a given port and pin.
 * @param      cfg       Pointer to configuration structure describing the pin
 * @param      callback  A pointer to a function of type #callback_fn.
 * @param      cbdata    The parameter to be passed to the callback function, #callback_fn, when an interrupt occurs.
 *
 */
void MXC_GPIO_RegisterCallback(const mxc_gpio_cfg_t *cfg, mxc_gpio_callback_fn callback,
                               void *cbdata);

/**
 * @brief      GPIO IRQ Handler. @note If a callback is registered for a given
 *             interrupt, the callback function will be called.
 *
 * @param      port Number of the port that generated the interrupt service routine.
 *
 */
void MXC_GPIO_Handler(unsigned int port);

/**
 * @brief      Set Voltage select for pins to VDDIO or VDDIOH
 *
 * @param      port  Pointer to the GPIO port registers
 * @param[in]  vssel  VDDIO or VDDIOH to set the voltatge to
 * @param[in]  mask   Pins in the GPIO port that will be set to the voltage.
 */
int MXC_GPIO_SetVSSEL(mxc_gpio_regs_t *port, mxc_gpio_vssel_t vssel, uint32_t mask);

/**
 * @brief      Enables GPIO pins to be used as a wakeup source.
 *
 * @param      port   The GPIO port
 * @param      mask   Pins in the GPIO port that will be enabled as a wakeup source.
 */
void MXC_GPIO_SetWakeEn(mxc_gpio_regs_t *port, uint32_t mask);

/**
 * @brief      Disables GPIO pins from being used as a wakeup source.
 *
 * @param      port   The GPIO port
 * @param      mask   Pins in the GPIO port that will be disabled as a wakeup source.
 */
void MXC_GPIO_ClearWakeEn(mxc_gpio_regs_t *port, uint32_t mask);

/**
 * @brief      Returns the pins currently enabled as wakeup sources.
 *
 * @param      port   The GPIO port to check.
 * 
 * @returns    The value of the wake enable register.
 */
uint32_t MXC_GPIO_GetWakeEn(mxc_gpio_regs_t *port);

/**
 * @brief      Set Drive Strength for pins.
 *
 * @param      port   The GPIO port.
 * @param[in]  ds     Drive strength level. Ref /mxc_gpio_ds_t enum type.
 * @param[in]  mask   Pins in the GPIO port that will be set to the voltage.
 */
int MXC_GPIO_SetDriveStrength(mxc_gpio_regs_t *port, mxc_gpio_drvstr_t drvstr, uint32_t mask);

/**
 * @brief      Enables/Disables the lock on all pins' configurations.  If 
 *             locked, any changes to a pin's configuration made through the
 *             MXC_GPIO_Config function will be ignored.
 *
 * @param      locked  Determines if changes will be allowed. */
void MXC_GPIO_SetConfigLock(mxc_gpio_config_lock_t locked);

/**
 * @brief      Reads the current lock state on pin configuration.
 *
 * @returns    The lock state. */
mxc_gpio_config_lock_t MXC_GPIO_GetConfigLock(void);

/**@} end of group gpio */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX32657_GPIO_H_
