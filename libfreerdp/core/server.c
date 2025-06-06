/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Server Channels
 *
 * Copyright 2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
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
 */

#include <freerdp/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <winpr/wtypes.h>
#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/stream.h>
#include <winpr/assert.h>
#include <winpr/cast.h>

#include <freerdp/log.h>
#include <freerdp/constants.h>
#include <freerdp/server/channels.h>
#include <freerdp/channels/drdynvc.h>
#include <freerdp/utils/drdynvc.h>

#include "rdp.h"

#include "server.h"

#define TAG FREERDP_TAG("core.server")
#ifdef WITH_DEBUG_DVC
#define DEBUG_DVC(...) WLog_DBG(TAG, __VA_ARGS__)
#else
#define DEBUG_DVC(...) \
	do                 \
	{                  \
	} while (0)
#endif

#define DVC_MAX_DATA_PDU_SIZE 1600

typedef struct
{
	UINT16 channelId;
	UINT16 reserved;
	UINT32 length;
	UINT32 offset;
} wtsChannelMessage;

static const DWORD g_err_oom = WINPR_CXX_COMPAT_CAST(DWORD, E_OUTOFMEMORY);

static DWORD g_SessionId = 1;
static wHashTable* g_ServerHandles = NULL;

static rdpPeerChannel* wts_get_dvc_channel_by_id(WTSVirtualChannelManager* vcm, UINT32 ChannelId)
{
	WINPR_ASSERT(vcm);
	return HashTable_GetItemValue(vcm->dynamicVirtualChannels, &ChannelId);
}

static BOOL wts_queue_receive_data(rdpPeerChannel* channel, const BYTE* Buffer, UINT32 Length)
{
	BYTE* buffer = NULL;
	wtsChannelMessage* messageCtx = NULL;

	WINPR_ASSERT(channel);
	messageCtx = (wtsChannelMessage*)malloc(sizeof(wtsChannelMessage) + Length);

	if (!messageCtx)
		return FALSE;

	WINPR_ASSERT(channel->channelId <= UINT16_MAX);
	messageCtx->channelId = (UINT16)channel->channelId;
	messageCtx->length = Length;
	messageCtx->offset = 0;
	buffer = (BYTE*)(messageCtx + 1);
	CopyMemory(buffer, Buffer, Length);
	return MessageQueue_Post(channel->queue, messageCtx, 0, NULL, NULL);
}

static BOOL wts_queue_send_item(rdpPeerChannel* channel, BYTE* Buffer, UINT32 Length)
{
	BYTE* buffer = NULL;
	UINT32 length = 0;

	WINPR_ASSERT(channel);
	WINPR_ASSERT(channel->vcm);
	buffer = Buffer;
	length = Length;

	WINPR_ASSERT(channel->channelId <= UINT16_MAX);
	const UINT16 channelId = (UINT16)channel->channelId;
	return MessageQueue_Post(channel->vcm->queue, (void*)(UINT_PTR)channelId, 0, (void*)buffer,
	                         (void*)(UINT_PTR)length);
}

static unsigned wts_read_variable_uint(wStream* s, int cbLen, UINT32* val)
{
	WINPR_ASSERT(s);
	WINPR_ASSERT(val);
	switch (cbLen)
	{
		case 0:
			if (!Stream_CheckAndLogRequiredLength(TAG, s, 1))
				return 0;

			Stream_Read_UINT8(s, *val);
			return 1;

		case 1:
			if (!Stream_CheckAndLogRequiredLength(TAG, s, 2))
				return 0;

			Stream_Read_UINT16(s, *val);
			return 2;

		case 2:
			if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
				return 0;

			Stream_Read_UINT32(s, *val);
			return 4;

		default:
			WLog_ERR(TAG, "invalid wts variable uint len %d", cbLen);
			return 0;
	}
}

static BOOL wts_read_drdynvc_capabilities_response(rdpPeerChannel* channel, UINT32 length)
{
	UINT16 Version = 0;

	WINPR_ASSERT(channel);
	WINPR_ASSERT(channel->vcm);
	if (length < 3)
		return FALSE;

	Stream_Seek_UINT8(channel->receiveData); /* Pad (1 byte) */
	Stream_Read_UINT16(channel->receiveData, Version);
	DEBUG_DVC("Version: %" PRIu16 "", Version);

	if (Version < 1)
	{
		WLog_ERR(TAG, "invalid version %" PRIu16 " for DRDYNVC", Version);
		return FALSE;
	}

	WTSVirtualChannelManager* vcm = channel->vcm;
	vcm->drdynvc_state = DRDYNVC_STATE_READY;

	/* we only support version 1 for now (no compression yet) */
	vcm->dvc_spoken_version = MAX(Version, 1);

	return SetEvent(MessageQueue_Event(vcm->queue));
}

static BOOL wts_read_drdynvc_create_response(rdpPeerChannel* channel, wStream* s, UINT32 length)
{
	UINT32 CreationStatus = 0;
	BOOL status = TRUE;

	WINPR_ASSERT(channel);
	WINPR_ASSERT(s);
	if (length < 4)
		return FALSE;

	Stream_Read_UINT32(s, CreationStatus);

	if ((INT32)CreationStatus < 0)
	{
		DEBUG_DVC("ChannelId %" PRIu32 " creation failed (%" PRId32 ")", channel->channelId,
		          (INT32)CreationStatus);
		channel->dvc_open_state = DVC_OPEN_STATE_FAILED;
	}
	else
	{
		DEBUG_DVC("ChannelId %" PRIu32 " creation succeeded", channel->channelId);
		channel->dvc_open_state = DVC_OPEN_STATE_SUCCEEDED;
	}

	channel->creationStatus = (INT32)CreationStatus;
	IFCALLRET(channel->vcm->dvc_creation_status, status, channel->vcm->dvc_creation_status_userdata,
	          channel->channelId, (INT32)CreationStatus);
	if (!status)
		WLog_ERR(TAG, "vcm->dvc_creation_status failed!");

	return status;
}

static BOOL wts_read_drdynvc_data_first(rdpPeerChannel* channel, wStream* s, int cbLen,
                                        UINT32 length)
{
	WINPR_ASSERT(channel);
	WINPR_ASSERT(s);
	const UINT32 value = wts_read_variable_uint(s, cbLen, &channel->dvc_total_length);

	if (value == 0)
		return FALSE;
	if (value > length)
		length = 0;
	else
		length -= value;

	if (length > channel->dvc_total_length)
		return FALSE;

	Stream_SetPosition(channel->receiveData, 0);

	if (!Stream_EnsureRemainingCapacity(channel->receiveData, channel->dvc_total_length))
		return FALSE;

	Stream_Write(channel->receiveData, Stream_ConstPointer(s), length);
	return TRUE;
}

static BOOL wts_read_drdynvc_data(rdpPeerChannel* channel, wStream* s, UINT32 length)
{
	BOOL ret = FALSE;

	WINPR_ASSERT(channel);
	WINPR_ASSERT(s);
	if (channel->dvc_total_length > 0)
	{
		if (Stream_GetPosition(channel->receiveData) + length > channel->dvc_total_length)
		{
			channel->dvc_total_length = 0;
			WLog_ERR(TAG, "incorrect fragment data, discarded.");
			return FALSE;
		}

		Stream_Write(channel->receiveData, Stream_ConstPointer(s), length);

		if (Stream_GetPosition(channel->receiveData) >= channel->dvc_total_length)
		{
			ret = wts_queue_receive_data(channel, Stream_Buffer(channel->receiveData),
			                             channel->dvc_total_length);
			channel->dvc_total_length = 0;
		}
		else
			ret = TRUE;
	}
	else
	{
		ret = wts_queue_receive_data(channel, Stream_ConstPointer(s), length);
	}

	return ret;
}

static void wts_read_drdynvc_close_response(rdpPeerChannel* channel)
{
	WINPR_ASSERT(channel);
	DEBUG_DVC("ChannelId %" PRIu32 " close response", channel->channelId);
	channel->dvc_open_state = DVC_OPEN_STATE_CLOSED;
	MessageQueue_PostQuit(channel->queue, 0);
}

static BOOL wts_read_drdynvc_pdu(rdpPeerChannel* channel)
{
	UINT8 Cmd = 0;
	UINT8 Sp = 0;
	UINT8 cbChId = 0;
	UINT32 ChannelId = 0;
	rdpPeerChannel* dvc = NULL;

	WINPR_ASSERT(channel);
	WINPR_ASSERT(channel->vcm);

	size_t length = Stream_GetPosition(channel->receiveData);

	if ((length < 1) || (length > UINT32_MAX))
		return FALSE;

	Stream_SetPosition(channel->receiveData, 0);
	const UINT8 value = Stream_Get_UINT8(channel->receiveData);
	length--;
	Cmd = (value & 0xf0) >> 4;
	Sp = (value & 0x0c) >> 2;
	cbChId = (value & 0x03) >> 0;

	if (Cmd == CAPABILITY_REQUEST_PDU)
		return wts_read_drdynvc_capabilities_response(channel, (UINT32)length);

	if (channel->vcm->drdynvc_state == DRDYNVC_STATE_READY)
	{
		BOOL haveChannelId = 0;
		switch (Cmd)
		{
			case SOFT_SYNC_REQUEST_PDU:
			case SOFT_SYNC_RESPONSE_PDU:
				haveChannelId = FALSE;
				break;
			default:
				haveChannelId = TRUE;
				break;
		}

		if (haveChannelId)
		{
			const unsigned val = wts_read_variable_uint(channel->receiveData, cbChId, &ChannelId);
			if (val == 0)
				return FALSE;

			length -= val;

			DEBUG_DVC("Cmd %s ChannelId %" PRIu32 " length %" PRIuz "",
			          drdynvc_get_packet_type(Cmd), ChannelId, length);
			dvc = wts_get_dvc_channel_by_id(channel->vcm, ChannelId);
			if (!dvc)
			{
				DEBUG_DVC("ChannelId %" PRIu32 " does not exist.", ChannelId);
				return TRUE;
			}
		}

		switch (Cmd)
		{
			case CREATE_REQUEST_PDU:
				return wts_read_drdynvc_create_response(dvc, channel->receiveData, (UINT32)length);

			case DATA_FIRST_PDU:
				if (dvc->dvc_open_state != DVC_OPEN_STATE_SUCCEEDED)
				{
					WLog_ERR(TAG,
					         "ChannelId %" PRIu32 " did not open successfully. "
					         "Ignoring DYNVC_DATA_FIRST PDU",
					         ChannelId);
					return TRUE;
				}

				return wts_read_drdynvc_data_first(dvc, channel->receiveData, Sp, (UINT32)length);

			case DATA_PDU:
				if (dvc->dvc_open_state != DVC_OPEN_STATE_SUCCEEDED)
				{
					WLog_ERR(TAG,
					         "ChannelId %" PRIu32 " did not open successfully. "
					         "Ignoring DYNVC_DATA PDU",
					         ChannelId);
					return TRUE;
				}

				return wts_read_drdynvc_data(dvc, channel->receiveData, (UINT32)length);

			case CLOSE_REQUEST_PDU:
				wts_read_drdynvc_close_response(dvc);
				break;

			case DATA_FIRST_COMPRESSED_PDU:
			case DATA_COMPRESSED_PDU:
				WLog_ERR(TAG, "Compressed data not handled");
				break;

			case SOFT_SYNC_RESPONSE_PDU:
				WLog_ERR(TAG, "SoftSync response not handled yet(and rather strange to receive "
				              "that packet as our code doesn't send SoftSync requests");
				break;

			case SOFT_SYNC_REQUEST_PDU:
				WLog_ERR(TAG, "Not expecting a SoftSyncRequest on the server");
				return FALSE;

			default:
				WLog_ERR(TAG, "Cmd %d not recognized.", Cmd);
				break;
		}
	}
	else
	{
		WLog_ERR(TAG, "received Cmd %d but channel is not ready.", Cmd);
	}

	return TRUE;
}

static int wts_write_variable_uint(wStream* s, UINT32 val)
{
	int cb = 0;

	WINPR_ASSERT(s);
	if (val <= 0xFF)
	{
		cb = 0;
		Stream_Write_UINT8(s, WINPR_ASSERTING_INT_CAST(uint8_t, val));
	}
	else if (val <= 0xFFFF)
	{
		cb = 1;
		Stream_Write_UINT16(s, WINPR_ASSERTING_INT_CAST(uint16_t, val));
	}
	else
	{
		cb = 2;
		Stream_Write_UINT32(s, val);
	}

	return cb;
}

static void wts_write_drdynvc_header(wStream* s, BYTE Cmd, UINT32 ChannelId)
{
	BYTE* bm = NULL;
	int cbChId = 0;

	WINPR_ASSERT(s);

	Stream_GetPointer(s, bm);
	Stream_Seek_UINT8(s);
	cbChId = wts_write_variable_uint(s, ChannelId);
	*bm = (((Cmd & 0x0F) << 4) | cbChId) & 0xFF;
}

static BOOL wts_write_drdynvc_create_request(wStream* s, UINT32 ChannelId, const char* ChannelName)
{
	size_t len = 0;

	WINPR_ASSERT(s);
	WINPR_ASSERT(ChannelName);

	wts_write_drdynvc_header(s, CREATE_REQUEST_PDU, ChannelId);
	len = strlen(ChannelName) + 1;

	if (!Stream_EnsureRemainingCapacity(s, len))
		return FALSE;

	Stream_Write(s, ChannelName, len);
	return TRUE;
}

static BOOL WTSProcessChannelData(rdpPeerChannel* channel, UINT16 channelId, const BYTE* data,
                                  size_t s, UINT32 flags, size_t t)
{
	BOOL ret = TRUE;
	const size_t size = s;
	const size_t totalSize = t;

	WINPR_ASSERT(channel);
	WINPR_ASSERT(channel->vcm);
	WINPR_UNUSED(channelId);

	if (flags & CHANNEL_FLAG_FIRST)
	{
		Stream_SetPosition(channel->receiveData, 0);
	}

	if (!Stream_EnsureRemainingCapacity(channel->receiveData, size))
		return FALSE;

	Stream_Write(channel->receiveData, data, size);

	if (flags & CHANNEL_FLAG_LAST)
	{
		if (Stream_GetPosition(channel->receiveData) != totalSize)
		{
			WLog_ERR(TAG, "read error");
		}

		if (channel == channel->vcm->drdynvc_channel)
		{
			ret = wts_read_drdynvc_pdu(channel);
		}
		else
		{
			const size_t pos = Stream_GetPosition(channel->receiveData);
			if (pos > UINT32_MAX)
				ret = FALSE;
			else
				ret = wts_queue_receive_data(channel, Stream_Buffer(channel->receiveData),
				                             (UINT32)pos);
		}

		Stream_SetPosition(channel->receiveData, 0);
	}

	return ret;
}

static BOOL WTSReceiveChannelData(freerdp_peer* client, UINT16 channelId, const BYTE* data,
                                  size_t size, UINT32 flags, size_t totalSize)
{
	rdpMcs* mcs = NULL;

	WINPR_ASSERT(client);
	WINPR_ASSERT(client->context);
	WINPR_ASSERT(client->context->rdp);

	mcs = client->context->rdp->mcs;
	WINPR_ASSERT(mcs);

	for (UINT32 i = 0; i < mcs->channelCount; i++)
	{
		rdpMcsChannel* cur = &mcs->channels[i];
		if (cur->ChannelId == channelId)
		{
			rdpPeerChannel* channel = (rdpPeerChannel*)cur->handle;

			if (channel)
				return WTSProcessChannelData(channel, channelId, data, size, flags, totalSize);
		}
	}

	WLog_WARN(TAG, "unknown channelId %" PRIu16 " ignored", channelId);

	return TRUE;
}

#if defined(WITH_FREERDP_DEPRECATED)
void WTSVirtualChannelManagerGetFileDescriptor(HANDLE hServer, void** fds, int* fds_count)
{
	void* fd = NULL;
	WTSVirtualChannelManager* vcm = (WTSVirtualChannelManager*)hServer;
	WINPR_ASSERT(vcm);
	WINPR_ASSERT(fds);
	WINPR_ASSERT(fds_count);

	fd = GetEventWaitObject(MessageQueue_Event(vcm->queue));

	if (fd)
	{
		fds[*fds_count] = fd;
		(*fds_count)++;
	}

#if 0

	if (vcm->drdynvc_channel)
	{
		fd = GetEventWaitObject(vcm->drdynvc_channel->receiveEvent);

		if (fd)
		{
			fds[*fds_count] = fd;
			(*fds_count)++;
		}
	}

#endif
}
#endif

BOOL WTSVirtualChannelManagerOpen(HANDLE hServer)
{
	WTSVirtualChannelManager* vcm = (WTSVirtualChannelManager*)hServer;

	if (!vcm)
		return FALSE;

	if (vcm->drdynvc_state == DRDYNVC_STATE_NONE)
	{
		rdpPeerChannel* channel = NULL;

		/* Initialize drdynvc channel once and only once. */
		vcm->drdynvc_state = DRDYNVC_STATE_INITIALIZED;
		channel = (rdpPeerChannel*)WTSVirtualChannelOpen((HANDLE)vcm, WTS_CURRENT_SESSION,
		                                                 DRDYNVC_SVC_CHANNEL_NAME);

		if (channel)
		{
			BYTE capaBuffer[12] = { 0 };
			wStream staticS = { 0 };
			wStream* s = Stream_StaticInit(&staticS, capaBuffer, sizeof(capaBuffer));

			vcm->drdynvc_channel = channel;
			vcm->dvc_spoken_version = 1;
			Stream_Write_UINT8(s, 0x50);    /* Cmd=5 sp=0 cbId=0 */
			Stream_Write_UINT8(s, 0x00);    /* Pad */
			Stream_Write_UINT16(s, 0x0001); /* Version */

			/* TODO: shall implement version 2 and 3 */

			const size_t pos = Stream_GetPosition(s);
			WINPR_ASSERT(pos <= UINT32_MAX);
			ULONG written = 0;
			if (!WTSVirtualChannelWrite(channel, (PCHAR)capaBuffer, (UINT32)pos, &written))
				return FALSE;
		}
	}

	return TRUE;
}

BOOL WTSVirtualChannelManagerCheckFileDescriptorEx(HANDLE hServer, BOOL autoOpen)
{
	wMessage message = { 0 };
	BOOL status = TRUE;
	WTSVirtualChannelManager* vcm = NULL;

	if (!hServer || hServer == INVALID_HANDLE_VALUE)
		return FALSE;

	vcm = (WTSVirtualChannelManager*)hServer;

	if (autoOpen)
	{
		if (!WTSVirtualChannelManagerOpen(hServer))
			return FALSE;
	}

	while (MessageQueue_Peek(vcm->queue, &message, TRUE))
	{
		BYTE* buffer = NULL;
		UINT32 length = 0;
		UINT16 channelId = 0;
		channelId = (UINT16)(UINT_PTR)message.context;
		buffer = (BYTE*)message.wParam;
		length = (UINT32)(UINT_PTR)message.lParam;

		WINPR_ASSERT(vcm->client);
		WINPR_ASSERT(vcm->client->SendChannelData);
		if (!vcm->client->SendChannelData(vcm->client, channelId, buffer, length))
		{
			status = FALSE;
		}

		free(buffer);

		if (!status)
			break;
	}

	return status;
}

BOOL WTSVirtualChannelManagerCheckFileDescriptor(HANDLE hServer)
{
	return WTSVirtualChannelManagerCheckFileDescriptorEx(hServer, TRUE);
}

HANDLE WTSVirtualChannelManagerGetEventHandle(HANDLE hServer)
{
	WTSVirtualChannelManager* vcm = (WTSVirtualChannelManager*)hServer;
	WINPR_ASSERT(vcm);
	return MessageQueue_Event(vcm->queue);
}

static rdpMcsChannel* wts_get_joined_channel_by_name(rdpMcs* mcs, const char* channel_name)
{
	if (!mcs || !channel_name || !strnlen(channel_name, CHANNEL_NAME_LEN + 1))
		return NULL;

	for (UINT32 index = 0; index < mcs->channelCount; index++)
	{
		rdpMcsChannel* mchannel = &mcs->channels[index];
		if (mchannel->joined)
		{
			if (_strnicmp(mchannel->Name, channel_name, CHANNEL_NAME_LEN + 1) == 0)
				return mchannel;
		}
	}

	return NULL;
}

static rdpMcsChannel* wts_get_joined_channel_by_id(rdpMcs* mcs, const UINT16 channel_id)
{
	if (!mcs || !channel_id)
		return NULL;

	WINPR_ASSERT(mcs->channels);
	for (UINT32 index = 0; index < mcs->channelCount; index++)
	{
		rdpMcsChannel* mchannel = &mcs->channels[index];
		if (mchannel->joined)
		{
			if (mchannel->ChannelId == channel_id)
				return &mcs->channels[index];
		}
	}

	return NULL;
}

BOOL WTSIsChannelJoinedByName(freerdp_peer* client, const char* channel_name)
{
	if (!client || !client->context || !client->context->rdp)
		return FALSE;

	return wts_get_joined_channel_by_name(client->context->rdp->mcs, channel_name) == NULL ? FALSE
	                                                                                       : TRUE;
}

BOOL WTSIsChannelJoinedById(freerdp_peer* client, UINT16 channel_id)
{
	if (!client || !client->context || !client->context->rdp)
		return FALSE;

	return wts_get_joined_channel_by_id(client->context->rdp->mcs, channel_id) == NULL ? FALSE
	                                                                                   : TRUE;
}

BOOL WTSVirtualChannelManagerIsChannelJoined(HANDLE hServer, const char* name)
{
	WTSVirtualChannelManager* vcm = (WTSVirtualChannelManager*)hServer;

	if (!vcm || !vcm->rdp)
		return FALSE;

	return wts_get_joined_channel_by_name(vcm->rdp->mcs, name) == NULL ? FALSE : TRUE;
}

BYTE WTSVirtualChannelManagerGetDrdynvcState(HANDLE hServer)
{
	WTSVirtualChannelManager* vcm = (WTSVirtualChannelManager*)hServer;
	WINPR_ASSERT(vcm);
	return vcm->drdynvc_state;
}

void WTSVirtualChannelManagerSetDVCCreationCallback(HANDLE hServer, psDVCCreationStatusCallback cb,
                                                    void* userdata)
{
	WTSVirtualChannelManager* vcm = hServer;

	WINPR_ASSERT(vcm);

	vcm->dvc_creation_status = cb;
	vcm->dvc_creation_status_userdata = userdata;
}

UINT16 WTSChannelGetId(freerdp_peer* client, const char* channel_name)
{
	rdpMcsChannel* channel = NULL;

	WINPR_ASSERT(channel_name);
	if (!client || !client->context || !client->context->rdp)
		return 0;

	channel = wts_get_joined_channel_by_name(client->context->rdp->mcs, channel_name);

	if (!channel)
		return 0;

	return channel->ChannelId;
}

UINT32 WTSChannelGetIdByHandle(HANDLE hChannelHandle)
{
	rdpPeerChannel* channel = hChannelHandle;

	WINPR_ASSERT(channel);

	return channel->channelId;
}

BOOL WTSChannelSetHandleByName(freerdp_peer* client, const char* channel_name, void* handle)
{
	rdpMcsChannel* channel = NULL;

	WINPR_ASSERT(channel_name);
	if (!client || !client->context || !client->context->rdp)
		return FALSE;

	channel = wts_get_joined_channel_by_name(client->context->rdp->mcs, channel_name);

	if (!channel)
		return FALSE;

	channel->handle = handle;
	return TRUE;
}

BOOL WTSChannelSetHandleById(freerdp_peer* client, UINT16 channel_id, void* handle)
{
	rdpMcsChannel* channel = NULL;

	if (!client || !client->context || !client->context->rdp)
		return FALSE;

	channel = wts_get_joined_channel_by_id(client->context->rdp->mcs, channel_id);

	if (!channel)
		return FALSE;

	channel->handle = handle;
	return TRUE;
}

void* WTSChannelGetHandleByName(freerdp_peer* client, const char* channel_name)
{
	rdpMcsChannel* channel = NULL;

	WINPR_ASSERT(channel_name);
	if (!client || !client->context || !client->context->rdp)
		return NULL;

	channel = wts_get_joined_channel_by_name(client->context->rdp->mcs, channel_name);

	if (!channel)
		return NULL;

	return channel->handle;
}

void* WTSChannelGetHandleById(freerdp_peer* client, UINT16 channel_id)
{
	rdpMcsChannel* channel = NULL;

	if (!client || !client->context || !client->context->rdp)
		return NULL;

	channel = wts_get_joined_channel_by_id(client->context->rdp->mcs, channel_id);

	if (!channel)
		return NULL;

	return channel->handle;
}

const char* WTSChannelGetName(freerdp_peer* client, UINT16 channel_id)
{
	rdpMcsChannel* channel = NULL;

	if (!client || !client->context || !client->context->rdp)
		return NULL;

	channel = wts_get_joined_channel_by_id(client->context->rdp->mcs, channel_id);

	if (!channel)
		return NULL;

	return (const char*)channel->Name;
}

char** WTSGetAcceptedChannelNames(freerdp_peer* client, size_t* count)
{
	rdpMcs* mcs = NULL;
	char** names = NULL;

	if (!client || !client->context || !count)
		return NULL;

	WINPR_ASSERT(client->context->rdp);
	mcs = client->context->rdp->mcs;
	WINPR_ASSERT(mcs);
	*count = mcs->channelCount;

	names = (char**)calloc(mcs->channelCount, sizeof(char*));
	if (!names)
		return NULL;

	for (UINT32 index = 0; index < mcs->channelCount; index++)
	{
		rdpMcsChannel* mchannel = &mcs->channels[index];
		names[index] = mchannel->Name;
	}

	return names;
}

INT64 WTSChannelGetOptions(freerdp_peer* client, UINT16 channel_id)
{
	rdpMcsChannel* channel = NULL;

	if (!client || !client->context || !client->context->rdp)
		return -1;

	channel = wts_get_joined_channel_by_id(client->context->rdp->mcs, channel_id);

	if (!channel)
		return -1;

	return (INT64)channel->options;
}

BOOL WINAPI FreeRDP_WTSStartRemoteControlSessionW(WINPR_ATTR_UNUSED LPWSTR pTargetServerName,
                                                  WINPR_ATTR_UNUSED ULONG TargetLogonId,
                                                  WINPR_ATTR_UNUSED BYTE HotkeyVk,
                                                  WINPR_ATTR_UNUSED USHORT HotkeyModifiers)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSStartRemoteControlSessionA(WINPR_ATTR_UNUSED LPSTR pTargetServerName,
                                                  WINPR_ATTR_UNUSED ULONG TargetLogonId,
                                                  WINPR_ATTR_UNUSED BYTE HotkeyVk,
                                                  WINPR_ATTR_UNUSED USHORT HotkeyModifiers)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSStartRemoteControlSessionExW(WINPR_ATTR_UNUSED LPWSTR pTargetServerName,
                                                    WINPR_ATTR_UNUSED ULONG TargetLogonId,
                                                    WINPR_ATTR_UNUSED BYTE HotkeyVk,
                                                    WINPR_ATTR_UNUSED USHORT HotkeyModifiers,
                                                    WINPR_ATTR_UNUSED DWORD flags)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSStartRemoteControlSessionExA(WINPR_ATTR_UNUSED LPSTR pTargetServerName,
                                                    WINPR_ATTR_UNUSED ULONG TargetLogonId,
                                                    WINPR_ATTR_UNUSED BYTE HotkeyVk,
                                                    WINPR_ATTR_UNUSED USHORT HotkeyModifiers,
                                                    WINPR_ATTR_UNUSED DWORD flags)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSStopRemoteControlSession(WINPR_ATTR_UNUSED ULONG LogonId)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSConnectSessionW(WINPR_ATTR_UNUSED ULONG LogonId,
                                       WINPR_ATTR_UNUSED ULONG TargetLogonId,
                                       WINPR_ATTR_UNUSED PWSTR pPassword,
                                       WINPR_ATTR_UNUSED BOOL bWait)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSConnectSessionA(WINPR_ATTR_UNUSED ULONG LogonId,
                                       WINPR_ATTR_UNUSED ULONG TargetLogonId,
                                       WINPR_ATTR_UNUSED PSTR pPassword,
                                       WINPR_ATTR_UNUSED BOOL bWait)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateServersW(WINPR_ATTR_UNUSED LPWSTR pDomainName,
                                         WINPR_ATTR_UNUSED DWORD Reserved,
                                         WINPR_ATTR_UNUSED DWORD Version,
                                         WINPR_ATTR_UNUSED PWTS_SERVER_INFOW* ppServerInfo,
                                         WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateServersA(WINPR_ATTR_UNUSED LPSTR pDomainName,
                                         WINPR_ATTR_UNUSED DWORD Reserved,
                                         WINPR_ATTR_UNUSED DWORD Version,
                                         WINPR_ATTR_UNUSED PWTS_SERVER_INFOA* ppServerInfo,
                                         WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

HANDLE WINAPI FreeRDP_WTSOpenServerW(WINPR_ATTR_UNUSED LPWSTR pServerName)
{
	WLog_ERR("TODO", "TODO: implement");
	return INVALID_HANDLE_VALUE;
}

static void wts_virtual_channel_manager_free_message(void* obj)
{
	wMessage* msg = (wMessage*)obj;

	if (msg)
	{
		BYTE* buffer = (BYTE*)msg->wParam;

		if (buffer)
			free(buffer);
	}
}

static void channel_free(rdpPeerChannel* channel)
{
	server_channel_common_free(channel);
}

static void array_channel_free(void* ptr)
{
	rdpPeerChannel* channel = ptr;
	channel_free(channel);
}

static BOOL dynChannelMatch(const void* v1, const void* v2)
{
	const UINT32* p1 = (const UINT32*)v1;
	const UINT32* p2 = (const UINT32*)v2;
	return *p1 == *p2;
}

static UINT32 channelId_Hash(const void* key)
{
	const UINT32* v = (const UINT32*)key;
	return *v;
}

HANDLE WINAPI FreeRDP_WTSOpenServerA(LPSTR pServerName)
{
	rdpContext* context = NULL;
	freerdp_peer* client = NULL;
	WTSVirtualChannelManager* vcm = NULL;
	HANDLE hServer = INVALID_HANDLE_VALUE;
	wObject queueCallbacks = { 0 };

	context = (rdpContext*)pServerName;

	if (!context)
		return INVALID_HANDLE_VALUE;

	client = context->peer;

	if (!client)
	{
		SetLastError(ERROR_INVALID_DATA);
		return INVALID_HANDLE_VALUE;
	}

	vcm = (WTSVirtualChannelManager*)calloc(1, sizeof(WTSVirtualChannelManager));

	if (!vcm)
		goto error_vcm_alloc;

	vcm->client = client;
	vcm->rdp = context->rdp;
	vcm->SessionId = g_SessionId++;

	if (!g_ServerHandles)
	{
		g_ServerHandles = HashTable_New(TRUE);

		if (!g_ServerHandles)
			goto error_free;
	}

	if (!HashTable_Insert(g_ServerHandles, (void*)(UINT_PTR)vcm->SessionId, (void*)vcm))
		goto error_free;

	queueCallbacks.fnObjectFree = wts_virtual_channel_manager_free_message;
	vcm->queue = MessageQueue_New(&queueCallbacks);

	if (!vcm->queue)
		goto error_queue;

	vcm->dvc_channel_id_seq = 0;
	vcm->dynamicVirtualChannels = HashTable_New(TRUE);

	if (!vcm->dynamicVirtualChannels)
		goto error_dynamicVirtualChannels;

	if (!HashTable_SetHashFunction(vcm->dynamicVirtualChannels, channelId_Hash))
		goto error_hashFunction;

	{
		wObject* obj = HashTable_ValueObject(vcm->dynamicVirtualChannels);
		WINPR_ASSERT(obj);
		obj->fnObjectFree = array_channel_free;

		obj = HashTable_KeyObject(vcm->dynamicVirtualChannels);
		obj->fnObjectEquals = dynChannelMatch;
	}
	client->ReceiveChannelData = WTSReceiveChannelData;
	hServer = (HANDLE)vcm;
	return hServer;

error_hashFunction:
	HashTable_Free(vcm->dynamicVirtualChannels);
error_dynamicVirtualChannels:
	MessageQueue_Free(vcm->queue);
error_queue:
	HashTable_Remove(g_ServerHandles, (void*)(UINT_PTR)vcm->SessionId);
error_free:
	free(vcm);
error_vcm_alloc:
	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return INVALID_HANDLE_VALUE;
}

HANDLE WINAPI FreeRDP_WTSOpenServerExW(WINPR_ATTR_UNUSED LPWSTR pServerName)
{
	WLog_ERR("TODO", "TODO: implement");
	return INVALID_HANDLE_VALUE;
}

HANDLE WINAPI FreeRDP_WTSOpenServerExA(LPSTR pServerName)
{
	return FreeRDP_WTSOpenServerA(pServerName);
}

VOID WINAPI FreeRDP_WTSCloseServer(HANDLE hServer)
{
	WTSVirtualChannelManager* vcm = NULL;
	vcm = (WTSVirtualChannelManager*)hServer;

	if (vcm && (vcm != INVALID_HANDLE_VALUE))
	{
		HashTable_Remove(g_ServerHandles, (void*)(UINT_PTR)vcm->SessionId);

		HashTable_Free(vcm->dynamicVirtualChannels);

		if (vcm->drdynvc_channel)
		{
			(void)WTSVirtualChannelClose(vcm->drdynvc_channel);
			vcm->drdynvc_channel = NULL;
		}

		MessageQueue_Free(vcm->queue);
		free(vcm);
	}
}

BOOL WINAPI FreeRDP_WTSEnumerateSessionsW(WINPR_ATTR_UNUSED HANDLE hServer,
                                          WINPR_ATTR_UNUSED DWORD Reserved,
                                          WINPR_ATTR_UNUSED DWORD Version,
                                          WINPR_ATTR_UNUSED PWTS_SESSION_INFOW* ppSessionInfo,
                                          WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateSessionsA(WINPR_ATTR_UNUSED HANDLE hServer,
                                          WINPR_ATTR_UNUSED DWORD Reserved,
                                          WINPR_ATTR_UNUSED DWORD Version,
                                          WINPR_ATTR_UNUSED PWTS_SESSION_INFOA* ppSessionInfo,
                                          WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateSessionsExW(WINPR_ATTR_UNUSED HANDLE hServer,
                                            WINPR_ATTR_UNUSED DWORD* pLevel,
                                            WINPR_ATTR_UNUSED DWORD Filter,
                                            WINPR_ATTR_UNUSED PWTS_SESSION_INFO_1W* ppSessionInfo,
                                            WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateSessionsExA(WINPR_ATTR_UNUSED HANDLE hServer,
                                            WINPR_ATTR_UNUSED DWORD* pLevel,
                                            WINPR_ATTR_UNUSED DWORD Filter,
                                            WINPR_ATTR_UNUSED PWTS_SESSION_INFO_1A* ppSessionInfo,
                                            WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateProcessesW(WINPR_ATTR_UNUSED HANDLE hServer,
                                           WINPR_ATTR_UNUSED DWORD Reserved,
                                           WINPR_ATTR_UNUSED DWORD Version,
                                           WINPR_ATTR_UNUSED PWTS_PROCESS_INFOW* ppProcessInfo,
                                           WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateProcessesA(WINPR_ATTR_UNUSED HANDLE hServer,
                                           WINPR_ATTR_UNUSED DWORD Reserved,
                                           WINPR_ATTR_UNUSED DWORD Version,
                                           WINPR_ATTR_UNUSED PWTS_PROCESS_INFOA* ppProcessInfo,
                                           WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSTerminateProcess(WINPR_ATTR_UNUSED HANDLE hServer,
                                        WINPR_ATTR_UNUSED DWORD ProcessId,
                                        WINPR_ATTR_UNUSED DWORD ExitCode)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSQuerySessionInformationW(WINPR_ATTR_UNUSED HANDLE hServer,
                                                WINPR_ATTR_UNUSED DWORD SessionId,
                                                WINPR_ATTR_UNUSED WTS_INFO_CLASS WTSInfoClass,
                                                WINPR_ATTR_UNUSED LPWSTR* ppBuffer,
                                                WINPR_ATTR_UNUSED DWORD* pBytesReturned)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSQuerySessionInformationA(HANDLE hServer, WINPR_ATTR_UNUSED DWORD SessionId,
                                                WTS_INFO_CLASS WTSInfoClass, LPSTR* ppBuffer,
                                                DWORD* pBytesReturned)
{
	DWORD BytesReturned = 0;
	WTSVirtualChannelManager* vcm = NULL;
	vcm = (WTSVirtualChannelManager*)hServer;

	if (!vcm)
		return FALSE;

	if (WTSInfoClass == WTSSessionId)
	{
		ULONG* pBuffer = NULL;
		BytesReturned = sizeof(ULONG);
		pBuffer = (ULONG*)malloc(sizeof(BytesReturned));

		if (!pBuffer)
		{
			SetLastError(g_err_oom);
			return FALSE;
		}

		*pBuffer = vcm->SessionId;
		*ppBuffer = (LPSTR)pBuffer;
		*pBytesReturned = BytesReturned;
		return TRUE;
	}

	return FALSE;
}

BOOL WINAPI FreeRDP_WTSQueryUserConfigW(WINPR_ATTR_UNUSED LPWSTR pServerName,
                                        WINPR_ATTR_UNUSED LPWSTR pUserName,
                                        WINPR_ATTR_UNUSED WTS_CONFIG_CLASS WTSConfigClass,
                                        WINPR_ATTR_UNUSED LPWSTR* ppBuffer,
                                        WINPR_ATTR_UNUSED DWORD* pBytesReturned)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSQueryUserConfigA(WINPR_ATTR_UNUSED LPSTR pServerName,
                                        WINPR_ATTR_UNUSED LPSTR pUserName,
                                        WINPR_ATTR_UNUSED WTS_CONFIG_CLASS WTSConfigClass,
                                        WINPR_ATTR_UNUSED LPSTR* ppBuffer,
                                        WINPR_ATTR_UNUSED DWORD* pBytesReturned)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSSetUserConfigW(WINPR_ATTR_UNUSED LPWSTR pServerName,
                                      WINPR_ATTR_UNUSED LPWSTR pUserName,
                                      WINPR_ATTR_UNUSED WTS_CONFIG_CLASS WTSConfigClass,
                                      WINPR_ATTR_UNUSED LPWSTR pBuffer,
                                      WINPR_ATTR_UNUSED DWORD DataLength)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSSetUserConfigA(WINPR_ATTR_UNUSED LPSTR pServerName,
                                      WINPR_ATTR_UNUSED LPSTR pUserName,
                                      WINPR_ATTR_UNUSED WTS_CONFIG_CLASS WTSConfigClass,
                                      WINPR_ATTR_UNUSED LPSTR pBuffer,
                                      WINPR_ATTR_UNUSED DWORD DataLength)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI
FreeRDP_WTSSendMessageW(WINPR_ATTR_UNUSED HANDLE hServer, WINPR_ATTR_UNUSED DWORD SessionId,
                        WINPR_ATTR_UNUSED LPWSTR pTitle, WINPR_ATTR_UNUSED DWORD TitleLength,
                        WINPR_ATTR_UNUSED LPWSTR pMessage, WINPR_ATTR_UNUSED DWORD MessageLength,
                        WINPR_ATTR_UNUSED DWORD Style, WINPR_ATTR_UNUSED DWORD Timeout,
                        WINPR_ATTR_UNUSED DWORD* pResponse, WINPR_ATTR_UNUSED BOOL bWait)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI
FreeRDP_WTSSendMessageA(WINPR_ATTR_UNUSED HANDLE hServer, WINPR_ATTR_UNUSED DWORD SessionId,
                        WINPR_ATTR_UNUSED LPSTR pTitle, WINPR_ATTR_UNUSED DWORD TitleLength,
                        WINPR_ATTR_UNUSED LPSTR pMessage, WINPR_ATTR_UNUSED DWORD MessageLength,
                        WINPR_ATTR_UNUSED DWORD Style, WINPR_ATTR_UNUSED DWORD Timeout,
                        WINPR_ATTR_UNUSED DWORD* pResponse, WINPR_ATTR_UNUSED BOOL bWait)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSDisconnectSession(WINPR_ATTR_UNUSED HANDLE hServer,
                                         WINPR_ATTR_UNUSED DWORD SessionId,
                                         WINPR_ATTR_UNUSED BOOL bWait)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSLogoffSession(WINPR_ATTR_UNUSED HANDLE hServer,
                                     WINPR_ATTR_UNUSED DWORD SessionId,
                                     WINPR_ATTR_UNUSED BOOL bWait)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSShutdownSystem(WINPR_ATTR_UNUSED HANDLE hServer,
                                      WINPR_ATTR_UNUSED DWORD ShutdownFlag)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSWaitSystemEvent(WINPR_ATTR_UNUSED HANDLE hServer,
                                       WINPR_ATTR_UNUSED DWORD EventMask,
                                       WINPR_ATTR_UNUSED DWORD* pEventFlags)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

static void peer_channel_queue_free_message(void* obj)
{
	wMessage* msg = (wMessage*)obj;
	if (!msg)
		return;

	free(msg->context);
	msg->context = NULL;
}

static rdpPeerChannel* channel_new(WTSVirtualChannelManager* vcm, freerdp_peer* client,
                                   UINT32 ChannelId, UINT16 index, UINT16 type, size_t chunkSize,
                                   const char* name)
{
	wObject queueCallbacks = { 0 };
	queueCallbacks.fnObjectFree = peer_channel_queue_free_message;

	rdpPeerChannel* channel =
	    server_channel_common_new(client, index, ChannelId, chunkSize, &queueCallbacks, name);

	WINPR_ASSERT(vcm);
	WINPR_ASSERT(client);

	if (!channel)
		goto fail;

	channel->vcm = vcm;
	channel->channelType = type;
	channel->creationStatus =
	    (type == RDP_PEER_CHANNEL_TYPE_SVC) ? ERROR_SUCCESS : ERROR_OPERATION_IN_PROGRESS;

	return channel;
fail:
	channel_free(channel);
	return NULL;
}

HANDLE WINAPI FreeRDP_WTSVirtualChannelOpen(HANDLE hServer, WINPR_ATTR_UNUSED DWORD SessionId,
                                            LPSTR pVirtualName)
{
	size_t length = 0;
	rdpMcs* mcs = NULL;
	rdpMcsChannel* joined_channel = NULL;
	freerdp_peer* client = NULL;
	rdpPeerChannel* channel = NULL;
	WTSVirtualChannelManager* vcm = NULL;
	HANDLE hChannelHandle = NULL;
	rdpContext* context = NULL;
	vcm = (WTSVirtualChannelManager*)hServer;

	if (!vcm)
	{
		SetLastError(ERROR_INVALID_DATA);
		return NULL;
	}

	client = vcm->client;
	WINPR_ASSERT(client);

	context = client->context;
	WINPR_ASSERT(context);
	WINPR_ASSERT(context->rdp);
	WINPR_ASSERT(context->settings);

	mcs = context->rdp->mcs;
	WINPR_ASSERT(mcs);

	length = strnlen(pVirtualName, CHANNEL_NAME_LEN + 1);

	if (length > CHANNEL_NAME_LEN)
	{
		SetLastError(ERROR_NOT_FOUND);
		return NULL;
	}

	UINT32 index = 0;
	for (; index < mcs->channelCount; index++)
	{
		rdpMcsChannel* mchannel = &mcs->channels[index];
		if (mchannel->joined && (strncmp(mchannel->Name, pVirtualName, length) == 0))
		{
			joined_channel = mchannel;
			break;
		}
	}

	if (!joined_channel)
	{
		SetLastError(ERROR_NOT_FOUND);
		return NULL;
	}

	channel = (rdpPeerChannel*)joined_channel->handle;

	if (!channel)
	{
		const UINT32 VCChunkSize =
		    freerdp_settings_get_uint32(context->settings, FreeRDP_VCChunkSize);

		WINPR_ASSERT(index <= UINT16_MAX);
		channel = channel_new(vcm, client, joined_channel->ChannelId, (UINT16)index,
		                      RDP_PEER_CHANNEL_TYPE_SVC, VCChunkSize, pVirtualName);

		if (!channel)
			goto fail;

		joined_channel->handle = channel;
	}

	hChannelHandle = (HANDLE)channel;
	return hChannelHandle;
fail:
	channel_free(channel);
	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return NULL;
}

HANDLE WINAPI FreeRDP_WTSVirtualChannelOpenEx(DWORD SessionId, LPSTR pVirtualName, DWORD flags)
{
	wStream* s = NULL;
	rdpMcs* mcs = NULL;
	BOOL joined = FALSE;
	freerdp_peer* client = NULL;
	rdpPeerChannel* channel = NULL;
	ULONG written = 0;
	WTSVirtualChannelManager* vcm = NULL;

	if (SessionId == WTS_CURRENT_SESSION)
		return NULL;

	vcm = (WTSVirtualChannelManager*)HashTable_GetItemValue(g_ServerHandles,
	                                                        (void*)(UINT_PTR)SessionId);

	if (!vcm)
		return NULL;

	if (!(flags & WTS_CHANNEL_OPTION_DYNAMIC))
	{
		return FreeRDP_WTSVirtualChannelOpen((HANDLE)vcm, SessionId, pVirtualName);
	}

	client = vcm->client;
	mcs = client->context->rdp->mcs;

	for (UINT32 index = 0; index < mcs->channelCount; index++)
	{
		rdpMcsChannel* mchannel = &mcs->channels[index];
		if (mchannel->joined &&
		    (strncmp(mchannel->Name, DRDYNVC_SVC_CHANNEL_NAME, CHANNEL_NAME_LEN + 1) == 0))
		{
			joined = TRUE;
			break;
		}
	}

	if (!joined)
	{
		SetLastError(ERROR_NOT_FOUND);
		return NULL;
	}

	if (!vcm->drdynvc_channel || (vcm->drdynvc_state != DRDYNVC_STATE_READY))
	{
		SetLastError(ERROR_NOT_READY);
		return NULL;
	}

	WINPR_ASSERT(client);
	WINPR_ASSERT(client->context);
	WINPR_ASSERT(client->context->settings);

	const UINT32 VCChunkSize =
	    freerdp_settings_get_uint32(client->context->settings, FreeRDP_VCChunkSize);
	channel = channel_new(vcm, client, 0, 0, RDP_PEER_CHANNEL_TYPE_DVC, VCChunkSize, pVirtualName);

	if (!channel)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}

	const LONG hdl = InterlockedIncrement(&vcm->dvc_channel_id_seq);
	channel->channelId = WINPR_ASSERTING_INT_CAST(uint32_t, hdl);

	if (!HashTable_Insert(vcm->dynamicVirtualChannels, &channel->channelId, channel))
	{
		channel_free(channel);
		channel = NULL;
		goto fail;
	}
	s = Stream_New(NULL, 64);

	if (!s)
		goto fail;

	if (!wts_write_drdynvc_create_request(s, channel->channelId, pVirtualName))
		goto fail;

	const size_t pos = Stream_GetPosition(s);
	WINPR_ASSERT(pos <= UINT32_MAX);
	if (!WTSVirtualChannelWrite(vcm->drdynvc_channel, Stream_BufferAs(s, char), (UINT32)pos,
	                            &written))
		goto fail;

	Stream_Free(s, TRUE);
	return channel;
fail:
	Stream_Free(s, TRUE);
	if (channel)
		HashTable_Remove(vcm->dynamicVirtualChannels, &channel->channelId);

	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return NULL;
}

BOOL WINAPI FreeRDP_WTSVirtualChannelClose(HANDLE hChannelHandle)
{
	wStream* s = NULL;
	rdpMcs* mcs = NULL;

	rdpPeerChannel* channel = (rdpPeerChannel*)hChannelHandle;
	BOOL ret = TRUE;

	if (channel)
	{
		WTSVirtualChannelManager* vcm = channel->vcm;

		WINPR_ASSERT(vcm);
		WINPR_ASSERT(vcm->client);
		WINPR_ASSERT(vcm->client->context);
		WINPR_ASSERT(vcm->client->context->rdp);
		mcs = vcm->client->context->rdp->mcs;

		if (channel->channelType == RDP_PEER_CHANNEL_TYPE_SVC)
		{
			if (channel->index < mcs->channelCount)
			{
				rdpMcsChannel* cur = &mcs->channels[channel->index];
				rdpPeerChannel* peerChannel = (rdpPeerChannel*)cur->handle;
				channel_free(peerChannel);
				cur->handle = NULL;
			}
		}
		else
		{
			if (channel->dvc_open_state == DVC_OPEN_STATE_SUCCEEDED)
			{
				ULONG written = 0;
				s = Stream_New(NULL, 8);

				if (!s)
				{
					WLog_ERR(TAG, "Stream_New failed!");
					ret = FALSE;
				}
				else
				{
					wts_write_drdynvc_header(s, CLOSE_REQUEST_PDU, channel->channelId);

					const size_t pos = Stream_GetPosition(s);
					WINPR_ASSERT(pos <= UINT32_MAX);
					ret = WTSVirtualChannelWrite(vcm->drdynvc_channel, Stream_BufferAs(s, char),
					                             (UINT32)pos, &written);
					Stream_Free(s, TRUE);
				}
			}
			HashTable_Remove(vcm->dynamicVirtualChannels, &channel->channelId);
		}
	}

	return ret;
}

BOOL WINAPI FreeRDP_WTSVirtualChannelRead(HANDLE hChannelHandle, WINPR_ATTR_UNUSED ULONG TimeOut,
                                          PCHAR Buffer, ULONG BufferSize, PULONG pBytesRead)
{
	BYTE* buffer = NULL;
	wMessage message = { 0 };
	wtsChannelMessage* messageCtx = NULL;
	rdpPeerChannel* channel = (rdpPeerChannel*)hChannelHandle;

	WINPR_ASSERT(channel);

	if (!MessageQueue_Peek(channel->queue, &message, FALSE))
	{
		SetLastError(ERROR_NO_DATA);
		*pBytesRead = 0;
		return FALSE;
	}

	messageCtx = message.context;

	if (messageCtx == NULL)
		return FALSE;

	buffer = (BYTE*)(messageCtx + 1);
	*pBytesRead = messageCtx->length - messageCtx->offset;

	if (Buffer == NULL || BufferSize == 0)
	{
		return TRUE;
	}

	if (*pBytesRead > BufferSize)
		*pBytesRead = BufferSize;

	CopyMemory(Buffer, buffer + messageCtx->offset, *pBytesRead);
	messageCtx->offset += *pBytesRead;

	if (messageCtx->offset >= messageCtx->length)
	{
		(void)MessageQueue_Peek(channel->queue, &message, TRUE);
		peer_channel_queue_free_message(&message);
	}

	return TRUE;
}

BOOL WINAPI FreeRDP_WTSVirtualChannelWrite(HANDLE hChannelHandle, PCHAR Buffer, ULONG uLength,
                                           PULONG pBytesWritten)
{
	wStream* s = NULL;
	int cbLen = 0;
	int cbChId = 0;
	int first = 0;
	BYTE* buffer = NULL;
	size_t totalWritten = 0;
	rdpPeerChannel* channel = (rdpPeerChannel*)hChannelHandle;
	BOOL ret = FALSE;

	if (!channel)
		return FALSE;

	EnterCriticalSection(&channel->writeLock);
	WINPR_ASSERT(channel->vcm);
	if (channel->channelType == RDP_PEER_CHANNEL_TYPE_SVC)
	{
		buffer = (BYTE*)malloc(uLength);

		if (!buffer)
		{
			SetLastError(g_err_oom);
			goto fail;
		}

		CopyMemory(buffer, Buffer, uLength);
		totalWritten = uLength;
		if (!wts_queue_send_item(channel, buffer, uLength))
			goto fail;
	}
	else if (!channel->vcm->drdynvc_channel || (channel->vcm->drdynvc_state != DRDYNVC_STATE_READY))
	{
		DEBUG_DVC("drdynvc not ready");
		goto fail;
	}
	else
	{
		first = TRUE;

		size_t Length = uLength;
		while (Length > 0)
		{
			s = Stream_New(NULL, DVC_MAX_DATA_PDU_SIZE);

			if (!s)
			{
				WLog_ERR(TAG, "Stream_New failed!");
				SetLastError(g_err_oom);
				goto fail;
			}

			buffer = Stream_Buffer(s);
			Stream_Seek_UINT8(s);
			cbChId = wts_write_variable_uint(s, channel->channelId);

			if (first && (Length > Stream_GetRemainingLength(s)))
			{
				cbLen = wts_write_variable_uint(s, WINPR_ASSERTING_INT_CAST(uint32_t, Length));
				buffer[0] = ((DATA_FIRST_PDU << 4) | (cbLen << 2) | cbChId) & 0xFF;
			}
			else
			{
				buffer[0] = ((DATA_PDU << 4) | cbChId) & 0xFF;
			}

			first = FALSE;
			size_t written = Stream_GetRemainingLength(s);

			if (written > Length)
				written = Length;

			Stream_Write(s, Buffer, written);
			const size_t length = Stream_GetPosition(s);
			Stream_Free(s, FALSE);
			if (length > UINT32_MAX)
				goto fail;
			Length -= written;
			Buffer += written;
			totalWritten += written;
			if (!wts_queue_send_item(channel->vcm->drdynvc_channel, buffer, (UINT32)length))
				goto fail;
		}
	}

	if (pBytesWritten)
		*pBytesWritten = WINPR_ASSERTING_INT_CAST(uint32_t, totalWritten);

	ret = TRUE;
fail:
	LeaveCriticalSection(&channel->writeLock);
	return ret;
}

BOOL WINAPI FreeRDP_WTSVirtualChannelPurgeInput(WINPR_ATTR_UNUSED HANDLE hChannelHandle)
{
	WLog_ERR("TODO", "TODO: implement");
	return TRUE;
}

BOOL WINAPI FreeRDP_WTSVirtualChannelPurgeOutput(WINPR_ATTR_UNUSED HANDLE hChannelHandle)
{
	WLog_ERR("TODO", "TODO: implement");
	return TRUE;
}

BOOL WINAPI FreeRDP_WTSVirtualChannelQuery(HANDLE hChannelHandle, WTS_VIRTUAL_CLASS WtsVirtualClass,
                                           PVOID* ppBuffer, DWORD* pBytesReturned)
{
	void* pfd = NULL;
	BOOL bval = 0;
	void* fds[10] = { 0 };
	HANDLE hEvent = NULL;
	int fds_count = 0;
	BOOL status = FALSE;
	rdpPeerChannel* channel = (rdpPeerChannel*)hChannelHandle;

	WINPR_ASSERT(channel);

	switch ((UINT32)WtsVirtualClass)
	{
		case WTSVirtualFileHandle:
			hEvent = MessageQueue_Event(channel->queue);
			pfd = GetEventWaitObject(hEvent);

			if (pfd)
			{
				fds[fds_count] = pfd;
				(fds_count)++;
			}

			*ppBuffer = malloc(sizeof(void*));

			if (!*ppBuffer)
			{
				SetLastError(g_err_oom);
			}
			else
			{
				CopyMemory(*ppBuffer, (void*)&fds[0], sizeof(void*));
				*pBytesReturned = sizeof(void*);
				status = TRUE;
			}

			break;

		case WTSVirtualEventHandle:
			hEvent = MessageQueue_Event(channel->queue);

			*ppBuffer = malloc(sizeof(HANDLE));

			if (!*ppBuffer)
			{
				SetLastError(g_err_oom);
			}
			else
			{
				CopyMemory(*ppBuffer, (void*)&hEvent, sizeof(HANDLE));
				*pBytesReturned = sizeof(void*);
				status = TRUE;
			}

			break;

		case WTSVirtualChannelReady:
			if (channel->channelType == RDP_PEER_CHANNEL_TYPE_SVC)
			{
				bval = TRUE;
				status = TRUE;
			}
			else
			{
				switch (channel->dvc_open_state)
				{
					case DVC_OPEN_STATE_NONE:
						bval = FALSE;
						status = TRUE;
						break;

					case DVC_OPEN_STATE_SUCCEEDED:
						bval = TRUE;
						status = TRUE;
						break;

					default:
						*ppBuffer = NULL;
						*pBytesReturned = 0;
						return FALSE;
				}
			}

			*ppBuffer = malloc(sizeof(BOOL));

			if (!*ppBuffer)
			{
				SetLastError(g_err_oom);
				status = FALSE;
			}
			else
			{
				CopyMemory(*ppBuffer, &bval, sizeof(BOOL));
				*pBytesReturned = sizeof(BOOL);
			}

			break;
		case WTSVirtualChannelOpenStatus:
		{
			INT32 value = channel->creationStatus;
			status = TRUE;

			*ppBuffer = malloc(sizeof(value));
			if (!*ppBuffer)
			{
				SetLastError(g_err_oom);
				status = FALSE;
			}
			else
			{
				CopyMemory(*ppBuffer, &value, sizeof(value));
				*pBytesReturned = sizeof(value);
			}
			break;
		}
		default:
			break;
	}

	return status;
}

VOID WINAPI FreeRDP_WTSFreeMemory(PVOID pMemory)
{
	free(pMemory);
}

BOOL WINAPI FreeRDP_WTSFreeMemoryExW(WINPR_ATTR_UNUSED WTS_TYPE_CLASS WTSTypeClass,
                                     WINPR_ATTR_UNUSED PVOID pMemory,
                                     WINPR_ATTR_UNUSED ULONG NumberOfEntries)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSFreeMemoryExA(WINPR_ATTR_UNUSED WTS_TYPE_CLASS WTSTypeClass,
                                     WINPR_ATTR_UNUSED PVOID pMemory,
                                     WINPR_ATTR_UNUSED ULONG NumberOfEntries)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSRegisterSessionNotification(WINPR_ATTR_UNUSED HWND hWnd,
                                                   WINPR_ATTR_UNUSED DWORD dwFlags)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSUnRegisterSessionNotification(WINPR_ATTR_UNUSED HWND hWnd)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSRegisterSessionNotificationEx(WINPR_ATTR_UNUSED HANDLE hServer,
                                                     WINPR_ATTR_UNUSED HWND hWnd,
                                                     WINPR_ATTR_UNUSED DWORD dwFlags)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSUnRegisterSessionNotificationEx(WINPR_ATTR_UNUSED HANDLE hServer,
                                                       WINPR_ATTR_UNUSED HWND hWnd)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSQueryUserToken(WINPR_ATTR_UNUSED ULONG SessionId,
                                      WINPR_ATTR_UNUSED PHANDLE phToken)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateProcessesExW(WINPR_ATTR_UNUSED HANDLE hServer,
                                             WINPR_ATTR_UNUSED DWORD* pLevel,
                                             WINPR_ATTR_UNUSED DWORD SessionId,
                                             WINPR_ATTR_UNUSED LPWSTR* ppProcessInfo,
                                             WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateProcessesExA(WINPR_ATTR_UNUSED HANDLE hServer,
                                             WINPR_ATTR_UNUSED DWORD* pLevel,
                                             WINPR_ATTR_UNUSED DWORD SessionId,
                                             WINPR_ATTR_UNUSED LPSTR* ppProcessInfo,
                                             WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateListenersW(WINPR_ATTR_UNUSED HANDLE hServer,
                                           WINPR_ATTR_UNUSED PVOID pReserved,
                                           WINPR_ATTR_UNUSED DWORD Reserved,
                                           WINPR_ATTR_UNUSED PWTSLISTENERNAMEW pListeners,
                                           WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSEnumerateListenersA(WINPR_ATTR_UNUSED HANDLE hServer,
                                           WINPR_ATTR_UNUSED PVOID pReserved,
                                           WINPR_ATTR_UNUSED DWORD Reserved,
                                           WINPR_ATTR_UNUSED PWTSLISTENERNAMEA pListeners,
                                           WINPR_ATTR_UNUSED DWORD* pCount)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSQueryListenerConfigW(WINPR_ATTR_UNUSED HANDLE hServer,
                                            WINPR_ATTR_UNUSED PVOID pReserved,
                                            WINPR_ATTR_UNUSED DWORD Reserved,
                                            WINPR_ATTR_UNUSED LPWSTR pListenerName,
                                            WINPR_ATTR_UNUSED PWTSLISTENERCONFIGW pBuffer)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSQueryListenerConfigA(WINPR_ATTR_UNUSED HANDLE hServer,
                                            WINPR_ATTR_UNUSED PVOID pReserved,
                                            WINPR_ATTR_UNUSED DWORD Reserved,
                                            WINPR_ATTR_UNUSED LPSTR pListenerName,
                                            WINPR_ATTR_UNUSED PWTSLISTENERCONFIGA pBuffer)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSCreateListenerW(WINPR_ATTR_UNUSED HANDLE hServer,
                                       WINPR_ATTR_UNUSED PVOID pReserved,
                                       WINPR_ATTR_UNUSED DWORD Reserved,
                                       WINPR_ATTR_UNUSED LPWSTR pListenerName,
                                       WINPR_ATTR_UNUSED PWTSLISTENERCONFIGW pBuffer,
                                       WINPR_ATTR_UNUSED DWORD flag)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSCreateListenerA(WINPR_ATTR_UNUSED HANDLE hServer,
                                       WINPR_ATTR_UNUSED PVOID pReserved,
                                       WINPR_ATTR_UNUSED DWORD Reserved,
                                       WINPR_ATTR_UNUSED LPSTR pListenerName,
                                       WINPR_ATTR_UNUSED PWTSLISTENERCONFIGA pBuffer,
                                       WINPR_ATTR_UNUSED DWORD flag)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSSetListenerSecurityW(
    WINPR_ATTR_UNUSED HANDLE hServer, WINPR_ATTR_UNUSED PVOID pReserved,
    WINPR_ATTR_UNUSED DWORD Reserved, WINPR_ATTR_UNUSED LPWSTR pListenerName,
    WINPR_ATTR_UNUSED SECURITY_INFORMATION SecurityInformation,
    WINPR_ATTR_UNUSED PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSSetListenerSecurityA(
    WINPR_ATTR_UNUSED HANDLE hServer, WINPR_ATTR_UNUSED PVOID pReserved,
    WINPR_ATTR_UNUSED DWORD Reserved, WINPR_ATTR_UNUSED LPSTR pListenerName,
    WINPR_ATTR_UNUSED SECURITY_INFORMATION SecurityInformation,
    WINPR_ATTR_UNUSED PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSGetListenerSecurityW(
    WINPR_ATTR_UNUSED HANDLE hServer, WINPR_ATTR_UNUSED PVOID pReserved,
    WINPR_ATTR_UNUSED DWORD Reserved, WINPR_ATTR_UNUSED LPWSTR pListenerName,
    WINPR_ATTR_UNUSED SECURITY_INFORMATION SecurityInformation,
    WINPR_ATTR_UNUSED PSECURITY_DESCRIPTOR pSecurityDescriptor, WINPR_ATTR_UNUSED DWORD nLength,
    WINPR_ATTR_UNUSED LPDWORD lpnLengthNeeded)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSGetListenerSecurityA(
    WINPR_ATTR_UNUSED HANDLE hServer, WINPR_ATTR_UNUSED PVOID pReserved,
    WINPR_ATTR_UNUSED DWORD Reserved, WINPR_ATTR_UNUSED LPSTR pListenerName,
    WINPR_ATTR_UNUSED SECURITY_INFORMATION SecurityInformation,
    WINPR_ATTR_UNUSED PSECURITY_DESCRIPTOR pSecurityDescriptor, WINPR_ATTR_UNUSED DWORD nLength,
    WINPR_ATTR_UNUSED LPDWORD lpnLengthNeeded)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL CDECL FreeRDP_WTSEnableChildSessions(WINPR_ATTR_UNUSED BOOL bEnable)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL CDECL FreeRDP_WTSIsChildSessionsEnabled(WINPR_ATTR_UNUSED PBOOL pbEnabled)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL CDECL FreeRDP_WTSGetChildSessionId(WINPR_ATTR_UNUSED PULONG pSessionId)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

DWORD WINAPI FreeRDP_WTSGetActiveConsoleSessionId(void)
{
	WLog_ERR("TODO", "TODO: implement");
	return 0xFFFFFFFF;
}
BOOL WINAPI FreeRDP_WTSLogoffUser(WINPR_ATTR_UNUSED HANDLE hServer)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

BOOL WINAPI FreeRDP_WTSLogonUser(WINPR_ATTR_UNUSED HANDLE hServer,
                                 WINPR_ATTR_UNUSED LPCSTR username,
                                 WINPR_ATTR_UNUSED LPCSTR password, WINPR_ATTR_UNUSED LPCSTR domain)
{
	WLog_ERR("TODO", "TODO: implement");
	return FALSE;
}

void server_channel_common_free(rdpPeerChannel* channel)
{
	if (!channel)
		return;
	MessageQueue_Free(channel->queue);
	Stream_Free(channel->receiveData, TRUE);
	DeleteCriticalSection(&channel->writeLock);
	free(channel);
}

rdpPeerChannel* server_channel_common_new(freerdp_peer* client, UINT16 index, UINT32 channelId,
                                          size_t chunkSize, const wObject* callback,
                                          const char* name)
{
	rdpPeerChannel* channel = (rdpPeerChannel*)calloc(1, sizeof(rdpPeerChannel));
	if (!channel)
		return NULL;

	InitializeCriticalSection(&channel->writeLock);

	channel->receiveData = Stream_New(NULL, chunkSize);
	if (!channel->receiveData)
		goto fail;

	channel->queue = MessageQueue_New(callback);
	if (!channel->queue)
		goto fail;

	channel->index = index;
	channel->client = client;
	channel->channelId = channelId;
	strncpy(channel->channelName, name, ARRAYSIZE(channel->channelName) - 1);
	return channel;
fail:
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_MISMATCHED_DEALLOC
	server_channel_common_free(channel);
	WINPR_PRAGMA_DIAG_POP
	return NULL;
}
