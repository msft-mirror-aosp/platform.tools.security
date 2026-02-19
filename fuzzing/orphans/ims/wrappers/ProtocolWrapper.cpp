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

extern "C" size_t
strlcpy(char *dst, const char *src, size_t size);

#include "rtp/RtpImpl.cpp"
#include "rtp/RtpService.cpp"
#include "rtp/core/RtcpAppPacket.cpp"
#include "rtp/core/RtcpByePacket.cpp"
#include "rtp/core/RtcpChunk.cpp"
#include "rtp/core/RtcpConfigInfo.cpp"
#include "rtp/core/RtcpFbPacket.cpp"
#include "rtp/core/RtcpHeader.cpp"
#include "rtp/core/RtcpPacket.cpp"
#include "rtp/core/RtcpReportBlock.cpp"
#include "rtp/core/RtcpRrPacket.cpp"
#include "rtp/core/RtcpSdesPacket.cpp"
#include "rtp/core/RtcpSrPacket.cpp"
#include "rtp/core/RtcpXrPacket.cpp"
#include "rtp/core/RtpHeader.cpp"
#include "rtp/core/RtpPacket.cpp"
#include "rtp/core/RtpPayloadInfo.cpp"
#include "rtp/core/RtpReceiverInfo.cpp"
#include "rtp/core/RtpSession.cpp"
#include "rtp/core/RtpSessionManager.cpp"
#include "rtp/core/RtpStack.cpp"
#include "rtp/core/RtpStackProfile.cpp"
#include "rtp/core/RtpStackUtil.cpp"
#include "rtp/core/RtpTimerInfo.cpp"
#include "rtp/utils/RtpBuffer.cpp"
#include "rtp/utils/RtpOsUtil.cpp"
