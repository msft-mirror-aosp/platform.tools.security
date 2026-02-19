/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <RtpPacket.h>
#include <RtpBuffer.h>

#include <ImsMediaTrace.h>

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    bool verbose = false;
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp((*argv)[i], "-verbose") == 0)
        {
            verbose = true;
            break;
        }
    }

    if (verbose)
    {
        ImsMediaTrace::IMSetLogMode(kLogEnableVerbose);
        ImsMediaTrace::IMSetDebugLogMode(kLogEnableVerbose);
    }
    else
    {
        ImsMediaTrace::IMSetLogMode(kLogEnableError);
        ImsMediaTrace::IMSetDebugLogMode(kLogEnableError);
        ImsMediaTrace::IMSetCaptureLogFile(true);
        ImsMediaTrace::IMSetLogFileName("/dev/null");
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    RtpPacket rtpPacket;
    RtpBuffer* pRtpBuf;
    uint8_t* pDataRtp;

    pDataRtp = new uint8_t[size];

    if (pDataRtp == nullptr)
    {
        return 0;
    }

    memcpy(pDataRtp, data, size);

    pRtpBuf = new RtpBuffer();

    if (pRtpBuf == nullptr)
    {
        delete[] pDataRtp;
        return 0;
    }

    pRtpBuf->setBufferInfo(size, pDataRtp);

    if (rtpPacket.decodePacket(pRtpBuf) == eRTP_SUCCESS)
    {
        // Round Trip: Encode the packet back
        uint32_t uiMaxLen = size > 2048 ? size * 2 : 2048;
        uint8_t* pOutData = new uint8_t[uiMaxLen];

        if (pOutData != nullptr)
        {
            RtpBuffer* pOutBuf = new RtpBuffer();

            if (pOutBuf != nullptr)
            {
                pOutBuf->setBufferInfo(uiMaxLen, pOutData);

                rtpPacket.formPacket(pOutBuf);
                delete pOutBuf;
            }
            else
            {
                delete[] pOutData;
            }
        }
    }

    delete pRtpBuf;
    return 0;
}
