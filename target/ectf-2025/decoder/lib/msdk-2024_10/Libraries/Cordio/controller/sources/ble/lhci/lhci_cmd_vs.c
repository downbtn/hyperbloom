/*************************************************************************************************/
/*!
 *  \file
 *
 *  \brief  Arm Ltd. vendor specific HCI command module implementation file.
 *
 *  Copyright (c) 2013-2019 Arm Ltd. All Rights Reserved.
 *
 *  Copyright (c) 2019-2020 Packetcraft, Inc.
 *
 *  Portions Copyright (c) 2024 Analog Devices, Inc.
 *  
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
/*************************************************************************************************/

#include "lhci_int.h"
#include "hci_defs.h"
#include "bb_ble_api.h"
#include "ll_api.h"
#include "pal_sys.h"
#include "sch_api.h"
#include "bb_ble_sniffer_api.h"
#include "wsf_assert.h"
#include "wsf_buf.h"
#include "wsf_cs.h"
#include "wsf_heap.h"
#include "wsf_math.h"
#include "wsf_msg.h"
#include "wsf_trace.h"
#include "util/bstream.h"
#include "bb_ble_api.h"
#include "flc.h"
#include "wsf_timer.h"
#include "pal_uart.h"
#include <string.h>

/**************************************************************************************************
  Macros
**************************************************************************************************/

/*! \brief      Maximum number of pool items. */
#define LHCI_MAX_POOL 5

/*! \brief      Get Pool Statistics command complete event length. */
#define LHCI_LEN_GET_POOL_STATS_EVT(n) (3 + (sizeof(WsfBufPoolStat_t) * (n)))

/*! \brief      Get System Statistics command complete event length. */
/* stackWatermark(uint16_t) +  palSysAssertCount(uint16_t) +
 * freeMem (uint32_t) + usedMem(uint32_t) + schDelayLoadTotalCount(uint32_t) +
 * connMax(uint16_t) +  connCtxSize(uint16_t) + csWatermarkUsec(uint16_t) + llHandlerWatermarkUsec(uint16_t) + schHandlerWatermarkUsec(uint16_t) + lhciHandlerWatermarkUsec(uint16_t) + schDelayLoadWatermarkCount(uint16_t) +
 * advSetMax(uint16_t) + advSetCtxSize(uint16_t) +
 * extScanMax(uint16_t) + extScanCtxSize(uint16_t) + extInitMax(uint16_t) + extInitCtxSize(uint16_t) + perScanMax(uint16_t) + perScanCtxSize(uint16_t) + cigMax(uint16_t) + cigCtxSize(uint16_t) + cisMax(uint16_t) + cisCtxSize(uint16_t) */

#define LHCI_LEN_GET_SYS_STATS_EVT                                                               \
    (2 * sizeof(uint16_t) + 3 * sizeof(uint32_t) + 7 * sizeof(uint16_t) + 2 * sizeof(uint16_t) + \
     10 * sizeof(uint16_t))

/**************************************************************************************************
  Functions
**************************************************************************************************/
//this is the callback function to the Msg
wsfHandlerId_t myTimerHandlerId;
wsfTimer_t myTimer;
void device_reset(wsfEventMask_t event, wsfMsgHdr_t *pMsg)
{
    NVIC_SystemReset();
    return;
}

/*************************************************************************************************/
/*!
 *  \brief  Decode Packetcraft common vendor specific HCI command packet.
 *
 *  \param  pHdr    Unpacked command header.
 *  \param  pBuf    Packed HCI packet buffer.
 *
 *  Command processing for vendor specific commands.
 *
 *  \return TRUE if opcode handled, FALSE otherwise.
 */
/*************************************************************************************************/
bool_t lhciCommonVsStdDecodeCmdPkt(LhciHdr_t *pHdr, uint8_t *pBuf)
{
    uint8_t status = HCI_SUCCESS;
    uint8_t evtParamLen = 1; /* default is status field only */
    uint32_t regReadAddr = 0;
    uint32_t channel = 0;

    (void)channel;

    /* Decode and consume command packet. */

    switch (pHdr->opCode) {
        /* --- extended device commands --- */
        

    case LHCI_OPCODE_VS_DEVICE_RESET: {
        LlReset();

        myTimerHandlerId = WsfOsSetNextHandler(device_reset);
        myTimer.handlerId = myTimerHandlerId;

        /*This delay is necessary here to let UART transfer the status back to hci*/
        WsfTimerStartMs(&myTimer, 5000);

        break;
    }

    case LHCI_OPCODE_VS_PAGE_ERASE: {
        uint32_t addr;
        BSTREAM_TO_UINT32(addr, pBuf);
        LL_TRACE_INFO1("Erase flash memory at address: %x", addr);
        if (addr % MXC_FLASH_PAGE_SIZE)
        {
            status = HCI_ERR_INVALID_PARAM; 
        }
        else
        {
            int error = MXC_FLC_PageErase(addr);
       
            if (error == E_NO_ERROR || error == E_BAD_PARAM) {
                LL_TRACE_INFO0("Done");
            
            }
            else{
                LL_TRACE_ERR0("Failed");
                status = HCI_ERR_HARDWARE_FAILURE;
            }
        }
        break;
    
    }

    case LHCI_OPCODE_VS_WRITE_FLASH: {
        uint32_t addr;
        BSTREAM_TO_UINT32(addr, pBuf);
        int error = E_NO_ERROR;

        error = MXC_FLC_Write(addr, (uint32_t) (pHdr->len - 4), (uint32_t*) pBuf);

        if (error != E_NO_ERROR) {
                LL_TRACE_ERR1("Writing to flash memory Failed! Error code: %d", error);
                status = HCI_ERR_HARDWARE_FAILURE;
        }
        
        break;
    }    

    case LHCI_OPCODE_VS_SET_OP_FLAGS: {
        uint32_t flags;
        bool_t enable;
        BSTREAM_TO_UINT32(flags, pBuf);
        BSTREAM_TO_UINT8(enable, pBuf);

        status = LlSetOpFlags(flags, enable);
        break;
    }
    case LHCI_OPCODE_VS_SET_EVENT_MASK: {
        bool_t enable;
        uint64_t mask;
        BSTREAM_TO_UINT64(mask, pBuf);
        BSTREAM_TO_UINT8(enable, pBuf);

        if (mask & ((uint64_t)LHCI_VS_EVT_MASK_SCAN_REPORT_EVT) << LHCI_BYTE_TO_BITS(0)) {
            LlScanReportEnable(enable);
        }

        if (mask & ((uint64_t)LHCI_VS_EVT_MASK_DIAG_TRACE_EVT) << LHCI_BYTE_TO_BITS(0)) {
            LL_TRACE_ENABLE(enable);
        }

#if (BT_VER >= LL_VER_BT_CORE_SPEC_5_2)
        /* TODO: Use function pointer to allow run time configuration of supported versions. */
        if (mask & ((uint64_t)LHCI_VS_EVT_MASK_ISO_EVENT_CMPL_EVT) << LHCI_BYTE_TO_BITS(0)) {
            LlIsoEventCompleteEnable(enable);
        }
#endif

        break;
    }
    case LHCI_OPCODE_VS_SET_TX_TEST_ERR_PATT: {
        uint32_t pattern;

        BSTREAM_TO_UINT32(pattern, pBuf);
        status = LlSetTxTestErrorPattern(pattern);
        break;
    }
    case LHCI_OPCODE_VS_SET_SNIFFER_ENABLE:
#if (BB_SNIFFER_ENABLED == TRUE)
        status = BbBleInitSniffer(pBuf[0], pBuf[1]);
#else
        status = HCI_ERR_UNKNOWN_CMD;
#endif
        break;

    case LHCI_OPCODE_VS_SET_BD_ADDR:
        LlSetBdAddr(pBuf);
        break;
    case LHCI_OPCODE_VS_GET_RAND_ADDR:
        status = LlGetRandAddr(pBuf);
        evtParamLen += sizeof(bdAddr_t);
        break;
    case LHCI_OPCODE_VS_SET_LOCAL_FEAT:
        status = LlSetFeatures(pBuf);
        break;
    case LHCI_OPCODE_VS_SET_DIAG_MODE:
        PalSysSetTrap(pBuf[0]);
        break;
    case LHCI_OPCODE_VS_GET_SYS_STATS:
        evtParamLen += LHCI_LEN_GET_SYS_STATS_EVT;
        break;
    case LHCI_OPCODE_VS_GET_TEST_STATS:
        evtParamLen += sizeof(BbBleDataPktStats_t);
        break;
    case LHCI_OPCODE_VS_GET_POOL_STATS:

#if WSF_BUF_STATS == TRUE
        evtParamLen += LHCI_LEN_GET_POOL_STATS_EVT(WSF_MIN(WsfBufGetNumPool(), LHCI_MAX_POOL));
#else
        status = HCI_ERR_CMD_DISALLOWED;
#endif
        break;
    case LHCI_OPCODE_VS_GET_PDU_FILT_STATS:
        evtParamLen += sizeof(BbBlePduFiltStats_t);
        break;

    case LHCI_OPCODE_VS_TX_TEST: {
        uint16_t numPackets = pBuf[4] | (pBuf[5] << 8);

        status = LlEnhancedTxTest(pBuf[0], pBuf[1], pBuf[2], pBuf[3], numPackets);
        break;
    }
    case LHCI_OPCODE_VS_RESET_TEST_STATS: {
        status = LL_SUCCESS;
        
        break;
    }
    case LHCI_OPCODE_VS_RX_TEST:
    {
        uint16_t numPackets = (pBuf[4] << 8) | pBuf[3];
        status = LlEnhancedRxTest(pBuf[0], pBuf[1], pBuf[2], numPackets);
        break;
    }
    case LHCI_OPCODE_VS_GET_RSSI:
    {
        #if 0
        channel = pBuf[0];

        if(channel > LL_DTM_MAX_CHAN_IDX)
        {
            status = LL_ERROR_CODE_PARAM_OUT_OF_MANDATORY_RANGE;
        }
        else{
            status = LL_SUCCESS;
        }
        evtParamLen += sizeof(int8_t);
        #else
        status = LL_ERROR_CODE_CMD_DISALLOWED;
        #endif

        break;
    }
    case LHCI_OPCODE_VS_FGEN:
    {
        #if 0
        uint8_t enable = pBuf[0];

        if(enable)
        {
            int8_t txPower = 0;
            uint32_t frequency_khz = pBuf[3] << 16  | pBuf[2] << 8 | pBuf[1];
            PalBbPatternType_t patternType = pBuf[4];

            status = LlGetAdvTxPower(&txPower);
            
            if(status != LL_SUCCESS)
            {
                break;
            }
            else if(PalBbFgenIsEnabled())
            {
                status = LL_ERROR_CODE_CMD_DISALLOWED;
            }
            else if(!PalBbIsValidPrbsType(patternType))
            {
                status = LL_ERROR_CODE_INVALID_HCI_CMD_PARAMS;
            }
            else{
                const bool freqOk = PalBbEnableFgen(frequency_khz, patternType, txPower);
                status = freqOk ? LL_SUCCESS : LL_ERROR_CODE_PARAM_OUT_OF_MANDATORY_RANGE;
            }


        }
        else
        {
            PalBbDisableFgen();
            status = LL_SUCCESS;
        }

        #else
        status = LL_ERROR_CODE_CMD_DISALLOWED;
        #endif

        break;
    }
    case LHCI_OPCODE_VS_RESET_ADV_STATS:
    {
        status = LL_SUCCESS;
        BbBleResetAdvStats();
        break;
    }
    case LHCI_OPCODE_VS_RESET_SCAN_STATS:
    {
        status = LL_SUCCESS;
        BbBleResetScanStats();
        break;
    }

    /* --- default --- */
    default:
        return FALSE; /* exit dispatcher routine */
    }

    uint8_t *pEvtBuf;

    /* Encode and send command complete event packet. */
    if ((pEvtBuf = lhciAllocCmdCmplEvt(evtParamLen, pHdr->opCode)) != NULL) {
        pBuf = pEvtBuf;
        pBuf += lhciPackCmdCompleteEvtStatus(pBuf, status);

        switch (pHdr->opCode) {
            /* --- extended device commands --- */

        case LHCI_OPCODE_VS_SET_OP_FLAGS:
        case LHCI_OPCODE_VS_SET_EVENT_MASK:
        case LHCI_OPCODE_VS_SET_BD_ADDR:
        case LHCI_OPCODE_VS_GET_RAND_ADDR:
        case LHCI_OPCODE_VS_SET_TX_TEST_ERR_PATT:
        case LHCI_OPCODE_VS_SET_SNIFFER_ENABLE:
        case LHCI_OPCODE_VS_RX_TEST:
        case LHCI_OPCODE_VS_TX_TEST:
        case LHCI_OPCODE_VS_RESET_ADV_STATS:
        case LHCI_OPCODE_VS_RESET_SCAN_STATS:
        case LHCI_OPCODE_VS_FGEN:

            /* no action */
            break;
        case LHCI_OPCODE_VS_GET_RSSI:
        {
            #if 0
            if(status != LL_SUCCESS)
            {
                break;
            }
        
            int8_t rssi = 0;
            PalBbGetRssi(&rssi, channel);
            

            pBuf[0] = (uint8_t)rssi;
            #else
            pBuf[0] = INT8_MIN;
            #endif
        
        

            break;
        }

        case LHCI_OPCODE_VS_RESET_TEST_STATS: {
            BbBleResetTestStats();
            break;
        }

        case LHCI_OPCODE_VS_SET_LOCAL_FEAT:
        case LHCI_OPCODE_VS_SET_DIAG_MODE:
            /* no action */
            break;

        case LHCI_OPCODE_VS_GET_SYS_STATS: {
            uint16_t stackWatermark = PalSysGetStackUsage();
            UINT16_TO_BSTREAM(pBuf, stackWatermark);
            UINT16_TO_BSTREAM(pBuf, PalSysGetAssertCount());

            uint32_t freeMem = WsfHeapCountAvailable();
            UINT32_TO_BSTREAM(pBuf, freeMem);
            uint32_t usedMem = WsfHeapCountUsed();
            UINT32_TO_BSTREAM(pBuf, usedMem);

            uint16_t connMax = 0;
            uint16_t connCtxSize;
            LlGetConnContextSize((uint8_t *)&connMax, &connCtxSize);
            UINT16_TO_BSTREAM(pBuf, connMax);
            UINT16_TO_BSTREAM(pBuf, connCtxSize);

#if (WSF_CS_STATS == TRUE)
            uint16_t csWatermarkUsec = WsfCsStatsGetCsWaterMark();
#else
            uint16_t csWatermarkUsec = 0;
#endif
            UINT16_TO_BSTREAM(pBuf, csWatermarkUsec);

            uint16_t llHandlerWatermarkUsec = LlStatsGetHandlerWatermarkUsec();
            UINT16_TO_BSTREAM(pBuf, llHandlerWatermarkUsec);
            uint16_t schHandlerWatermarkUsec = SchStatsGetHandlerWatermarkUsec();
            UINT16_TO_BSTREAM(pBuf, schHandlerWatermarkUsec);
            UINT16_TO_BSTREAM(pBuf, lhciHandlerWatermarkUsec);

            uint16_t advSetMax = 0;
            uint16_t advSetCtxSize;
            LlGetAdvSetContextSize((uint8_t *)&advSetMax, &advSetCtxSize);
            UINT16_TO_BSTREAM(pBuf, advSetMax);
            UINT16_TO_BSTREAM(pBuf, advSetCtxSize);

            uint16_t extScanMax = 0;
            uint16_t extScanCtxSize;
            LlGetExtScanContextSize((uint8_t *)&extScanMax, &extScanCtxSize);
            UINT16_TO_BSTREAM(pBuf, extScanMax);
            UINT16_TO_BSTREAM(pBuf, extScanCtxSize);

            uint16_t extInitMax = 0;
            uint16_t extInitCtxSize;
            LlGetExtInitContextSize((uint8_t *)&extInitMax, &extInitCtxSize);
            UINT16_TO_BSTREAM(pBuf, extInitMax);
            UINT16_TO_BSTREAM(pBuf, extInitCtxSize);

            uint16_t perScanMax = 0;
            uint16_t perScanCtxSize;
            LlGetPerScanContextSize((uint8_t *)&perScanMax, &perScanCtxSize);
            UINT16_TO_BSTREAM(pBuf, perScanMax);
            UINT16_TO_BSTREAM(pBuf, perScanCtxSize);

            uint16_t cigMax = 0;
            uint16_t cigCtxSize;
            LlGetCigContextSize((uint8_t *)&cigMax, &cigCtxSize);
            UINT16_TO_BSTREAM(pBuf, cigMax);
            UINT16_TO_BSTREAM(pBuf, cigCtxSize);

            uint16_t cisMax = 0;
            uint16_t cisCtxSize;
            LlGetCisContextSize((uint8_t *)&cisMax, &cisCtxSize);
            UINT16_TO_BSTREAM(pBuf, cisMax);
            UINT16_TO_BSTREAM(pBuf, cisCtxSize);

            break;
        }
        case LHCI_OPCODE_VS_GET_TEST_STATS: {
            BbBleDataPktStats_t stats;
            BbBleGetTestStats(&stats);
            memcpy(pBuf, (uint8_t *)&stats, sizeof(stats));
            break;
        }
#if WSF_BUF_STATS == TRUE
        case LHCI_OPCODE_VS_GET_POOL_STATS: {
            unsigned int i;
            WsfBufPoolStat_t stats;
            const uint8_t numPool = WSF_MIN(WsfBufGetNumPool(), LHCI_MAX_POOL);

            UINT8_TO_BSTREAM(pBuf, numPool);

            for (i = 0; i < numPool; i++) {
                WsfBufGetPoolStats(&stats, i);
                UINT16_TO_BSTREAM(pBuf, stats.bufSize);
                UINT8_TO_BSTREAM(pBuf, stats.numBuf);
                UINT8_TO_BSTREAM(pBuf, stats.numAlloc);
                UINT8_TO_BSTREAM(pBuf, stats.maxAlloc);
                UINT16_TO_BSTREAM(pBuf, stats.maxReqLen);
            }
            break;
        }
#endif
        case LHCI_OPCODE_VS_GET_PDU_FILT_STATS: {
            BbBlePduFiltStats_t stats;
            BbBleGetPduFiltStats(&stats);
            memcpy(pBuf, (uint8_t *)&stats, sizeof(stats));
            break;
        }

            /* --- default --- */

        default:
            break;
        }

        lhciSendCmdCmplEvt(pEvtBuf);
    }

    return TRUE;
}
