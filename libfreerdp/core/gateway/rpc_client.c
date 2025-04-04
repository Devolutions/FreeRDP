/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RPC Client
 *
 * Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <freerdp/log.h>

#include <winpr/crt.h>
#include <winpr/wtypes.h>
#include <winpr/assert.h>
#include <winpr/cast.h>
#include <winpr/print.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <winpr/stream.h>

#include "http.h"
#include "ncacn_http.h"

#include "rpc_bind.h"
#include "rpc_fault.h"
#include "rpc_client.h"
#include "rts_signature.h"

#include "../utils.h"
#include "../rdp.h"
#include "../proxy.h"

#define TAG FREERDP_TAG("core.gateway.rpc")

static const char* rpc_client_state_str(RPC_CLIENT_STATE state)
{
	// NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
	const char* str = "RPC_CLIENT_STATE_UNKNOWN";

	switch (state)
	{
		case RPC_CLIENT_STATE_INITIAL:
			str = "RPC_CLIENT_STATE_INITIAL";
			break;

		case RPC_CLIENT_STATE_ESTABLISHED:
			str = "RPC_CLIENT_STATE_ESTABLISHED";
			break;

		case RPC_CLIENT_STATE_WAIT_SECURE_BIND_ACK:
			str = "RPC_CLIENT_STATE_WAIT_SECURE_BIND_ACK";
			break;

		case RPC_CLIENT_STATE_WAIT_UNSECURE_BIND_ACK:
			str = "RPC_CLIENT_STATE_WAIT_UNSECURE_BIND_ACK";
			break;

		case RPC_CLIENT_STATE_WAIT_SECURE_ALTER_CONTEXT_RESPONSE:
			str = "RPC_CLIENT_STATE_WAIT_SECURE_ALTER_CONTEXT_RESPONSE";
			break;

		case RPC_CLIENT_STATE_CONTEXT_NEGOTIATED:
			str = "RPC_CLIENT_STATE_CONTEXT_NEGOTIATED";
			break;

		case RPC_CLIENT_STATE_WAIT_RESPONSE:
			str = "RPC_CLIENT_STATE_WAIT_RESPONSE";
			break;

		case RPC_CLIENT_STATE_FINAL:
			str = "RPC_CLIENT_STATE_FINAL";
			break;
		default:
			break;
	}
	return str;
}

static void rpc_pdu_reset(RPC_PDU* pdu)
{
	pdu->Type = 0;
	pdu->Flags = 0;
	pdu->CallId = 0;
	Stream_SetPosition(pdu->s, 0);
	Stream_SetLength(pdu->s, 0);
}

static RPC_PDU* rpc_pdu_new(void)
{
	RPC_PDU* pdu = NULL;
	pdu = (RPC_PDU*)malloc(sizeof(RPC_PDU));

	if (!pdu)
		return NULL;

	pdu->s = Stream_New(NULL, 4096);

	if (!pdu->s)
	{
		free(pdu);
		return NULL;
	}

	rpc_pdu_reset(pdu);
	return pdu;
}

static void rpc_pdu_free(RPC_PDU* pdu)
{
	if (!pdu)
		return;

	Stream_Free(pdu->s, TRUE);
	free(pdu);
}

static int rpc_client_receive_pipe_write(RpcClient* client, const BYTE* buffer, size_t length)
{
	int status = 0;

	if (!client || !buffer)
		return -1;

	EnterCriticalSection(&(client->PipeLock));

	if (ringbuffer_write(&(client->ReceivePipe), buffer, length))
		status += (int)length;

	if (ringbuffer_used(&(client->ReceivePipe)) > 0)
		(void)SetEvent(client->PipeEvent);

	LeaveCriticalSection(&(client->PipeLock));
	return status;
}

int rpc_client_receive_pipe_read(RpcClient* client, BYTE* buffer, size_t length)
{
	size_t status = 0;
	int nchunks = 0;
	DataChunk chunks[2];

	if (!client || !buffer)
		return -1;

	EnterCriticalSection(&(client->PipeLock));
	nchunks = ringbuffer_peek(&(client->ReceivePipe), chunks, length);

	for (int index = 0; index < nchunks; index++)
	{
		CopyMemory(&buffer[status], chunks[index].data, chunks[index].size);
		status += chunks[index].size;
	}

	if (status > 0)
		ringbuffer_commit_read_bytes(&(client->ReceivePipe), status);

	if (ringbuffer_used(&(client->ReceivePipe)) < 1)
		(void)ResetEvent(client->PipeEvent);

	LeaveCriticalSection(&(client->PipeLock));

	if (status > INT_MAX)
		return -1;
	return (int)status;
}

static int rpc_client_transition_to_state(rdpRpc* rpc, RPC_CLIENT_STATE state)
{
	int status = 1;

	rpc->State = state;
	WLog_DBG(TAG, "%s", rpc_client_state_str(state));
	return status;
}

static int rpc_client_recv_pdu_int(rdpRpc* rpc, RPC_PDU* pdu)
{
	int status = -1;
	RtsPduSignature found = { 0 };

	WINPR_ASSERT(rpc);
	WINPR_ASSERT(pdu);

	rdpTsg* tsg = transport_get_tsg(rpc->transport);

	WLog_Print(rpc->log, WLOG_TRACE, "client state %s, vc state %s",
	           rpc_client_state_str(rpc->State), rpc_vc_state_str(rpc->VirtualConnection->State));

	const BOOL rc = rts_match_pdu_signature_ex(&RTS_PDU_PING_SIGNATURE, pdu->s, NULL, &found, TRUE);
	rts_print_pdu_signature(rpc->log, WLOG_TRACE, &found);
	if (rc)
		return rts_recv_ping_pdu(rpc, pdu->s);

	if (rpc->VirtualConnection->State < VIRTUAL_CONNECTION_STATE_OPENED)
	{
		switch (rpc->VirtualConnection->State)
		{
			case VIRTUAL_CONNECTION_STATE_INITIAL:
				break;

			case VIRTUAL_CONNECTION_STATE_OUT_CHANNEL_WAIT:
				break;

			case VIRTUAL_CONNECTION_STATE_WAIT_A3W:
				if (memcmp(&found, &RTS_PDU_CONN_A3_SIGNATURE, sizeof(found)) != 0)
				{
					WLog_Print(rpc->log, WLOG_ERROR, "unexpected RTS PDU: Expected CONN/A3");
					rts_print_pdu_signature(rpc->log, WLOG_ERROR, &found);
					return -1;
				}

				if (!rts_recv_CONN_A3_pdu(rpc, pdu->s))
				{
					WLog_Print(rpc->log, WLOG_ERROR, "rts_recv_CONN_A3_pdu failure");
					return -1;
				}

				rpc_virtual_connection_transition_to_state(rpc, rpc->VirtualConnection,
				                                           VIRTUAL_CONNECTION_STATE_WAIT_C2);
				status = 1;
				break;

			case VIRTUAL_CONNECTION_STATE_WAIT_C2:
				if (memcmp(&found, &RTS_PDU_CONN_C2_SIGNATURE, sizeof(found)) != 0)
				{
					WLog_Print(rpc->log, WLOG_ERROR, "unexpected RTS PDU: Expected CONN/C2");
					rts_print_pdu_signature(rpc->log, WLOG_ERROR, &found);
					return -1;
				}

				if (!rts_recv_CONN_C2_pdu(rpc, pdu->s))
				{
					WLog_Print(rpc->log, WLOG_ERROR, "rts_recv_CONN_C2_pdu failure");
					return -1;
				}

				rpc_virtual_connection_transition_to_state(rpc, rpc->VirtualConnection,
				                                           VIRTUAL_CONNECTION_STATE_OPENED);
				rpc_client_transition_to_state(rpc, RPC_CLIENT_STATE_ESTABLISHED);

				if (rpc_send_bind_pdu(rpc, TRUE) < 0)
				{
					WLog_Print(rpc->log, WLOG_ERROR, "rpc_send_bind_pdu failure");
					return -1;
				}

				rpc_client_transition_to_state(rpc, RPC_CLIENT_STATE_WAIT_SECURE_BIND_ACK);
				status = 1;
				break;

			case VIRTUAL_CONNECTION_STATE_OPENED:
				break;

			case VIRTUAL_CONNECTION_STATE_FINAL:
				break;
			default:
				break;
		}
	}
	else if (rpc->State < RPC_CLIENT_STATE_CONTEXT_NEGOTIATED)
	{
		if (rpc->State == RPC_CLIENT_STATE_WAIT_SECURE_BIND_ACK)
		{
			if (pdu->Type == PTYPE_BIND_ACK || pdu->Type == PTYPE_ALTER_CONTEXT_RESP)
			{
				if (!rpc_recv_bind_ack_pdu(rpc, pdu->s))
				{
					WLog_Print(rpc->log, WLOG_ERROR, "rpc_recv_bind_ack_pdu failure");
					return -1;
				}
			}
			else
			{
				WLog_Print(rpc->log, WLOG_ERROR,
				           "RPC_CLIENT_STATE_WAIT_SECURE_BIND_ACK unexpected pdu type: 0x%08" PRIX32
				           "",
				           pdu->Type);
				return -1;
			}

			switch (rpc_bind_state(rpc))
			{
				case RPC_BIND_STATE_INCOMPLETE:
					if (rpc_send_bind_pdu(rpc, FALSE) < 0)
					{
						WLog_Print(rpc->log, WLOG_ERROR, "rpc_send_bind_pdu failure");
						return -1;
					}
					break;
				case RPC_BIND_STATE_LAST_LEG:
					if (rpc_send_rpc_auth_3_pdu(rpc) < 0)
					{
						WLog_Print(rpc->log, WLOG_ERROR,
						           "rpc_secure_bind: error sending rpc_auth_3 pdu!");
						return -1;
					}
					/* fallthrough */
					WINPR_FALLTHROUGH
				case RPC_BIND_STATE_COMPLETE:
					rpc_client_transition_to_state(rpc, RPC_CLIENT_STATE_CONTEXT_NEGOTIATED);

					if (!tsg_proxy_begin(tsg))
					{
						WLog_Print(rpc->log, WLOG_ERROR, "tsg_proxy_begin failure");
						return -1;
					}
					break;
				default:
					break;
			}

			status = 1;
		}
		else
		{
			WLog_Print(rpc->log, WLOG_ERROR, "invalid rpc->State: %d", rpc->State);
		}
	}
	else if (rpc->State >= RPC_CLIENT_STATE_CONTEXT_NEGOTIATED)
	{
		if (!tsg_recv_pdu(tsg, pdu))
			status = -1;
		else
			status = 1;
	}

	return status;
}

static int rpc_client_recv_pdu(rdpRpc* rpc, RPC_PDU* pdu)
{
	WINPR_ASSERT(rpc);
	WINPR_ASSERT(pdu);

	Stream_SealLength(pdu->s);
	Stream_SetPosition(pdu->s, 0);

	const size_t before = Stream_GetRemainingLength(pdu->s);
	WLog_Print(rpc->log, WLOG_TRACE, "RPC PDU parsing %" PRIuz " bytes", before);
	const int rc = rpc_client_recv_pdu_int(rpc, pdu);
	if (rc < 0)
		return rc;
	const size_t after = Stream_GetRemainingLength(pdu->s);
	if (after > 0)
	{
		/* Just log so we do not fail if we have some unprocessed padding bytes */
		WLog_Print(rpc->log, WLOG_WARN, "Incompletely parsed RPC PDU (%" PRIuz " bytes remain)",
		           after);
	}

	return rc;
}

static int rpc_client_recv_fragment(rdpRpc* rpc, wStream* fragment)
{
	int rc = -1;
	RPC_PDU* pdu = NULL;
	size_t StubOffset = 0;
	size_t StubLength = 0;
	RpcClientCall* call = NULL;
	rpcconn_hdr_t header = { 0 };

	WINPR_ASSERT(rpc);
	WINPR_ASSERT(rpc->client);
	WINPR_ASSERT(fragment);

	pdu = rpc->client->pdu;
	WINPR_ASSERT(pdu);

	Stream_SealLength(fragment);
	Stream_SetPosition(fragment, 0);

	if (!rts_read_pdu_header(fragment, &header))
		goto fail;

	if (header.common.ptype == PTYPE_RESPONSE)
	{
		rpc->VirtualConnection->DefaultOutChannel->BytesReceived += header.common.frag_length;
		rpc->VirtualConnection->DefaultOutChannel->ReceiverAvailableWindow -=
		    header.common.frag_length;

		if (rpc->VirtualConnection->DefaultOutChannel->ReceiverAvailableWindow <
		    (rpc->ReceiveWindow / 2))
		{
			if (!rts_send_flow_control_ack_pdu(rpc))
				goto fail;
		}

		if (!rpc_get_stub_data_info(rpc, &header, &StubOffset, &StubLength))
		{
			WLog_ERR(TAG, "expected stub");
			goto fail;
		}

		if (StubLength == 4)
		{
			if ((header.common.call_id == rpc->PipeCallId) &&
			    (header.common.pfc_flags & PFC_LAST_FRAG))
			{
				/* End of TsProxySetupReceivePipe */
				TerminateEventArgs e;
				rdpContext* context = transport_get_context(rpc->transport);
				rdpTsg* tsg = transport_get_tsg(rpc->transport);

				WINPR_ASSERT(context);

				if (Stream_Length(fragment) < StubOffset + 4)
					goto fail;
				Stream_SetPosition(fragment, StubOffset);
				Stream_Read_UINT32(fragment, rpc->result);

				utils_abort_connect(context->rdp);
				tsg_set_state(tsg, TSG_STATE_TUNNEL_CLOSE_PENDING);
				EventArgsInit(&e, "freerdp");
				e.code = 0;
				PubSub_OnTerminate(context->rdp->pubSub, context, &e);
				rc = 0;
				goto success;
			}

			if (header.common.call_id != rpc->PipeCallId)
			{
				/* Ignoring non-TsProxySetupReceivePipe Response */
				rc = 0;
				goto success;
			}
		}

		if (rpc->StubFragCount == 0)
			rpc->StubCallId = header.common.call_id;

		if (rpc->StubCallId != header.common.call_id)
		{
			WLog_ERR(TAG,
			         "invalid call_id: actual: %" PRIu32 ", expected: %" PRIu32
			         ", frag_count: %" PRIu32 "",
			         rpc->StubCallId, header.common.call_id, rpc->StubFragCount);
		}

		call = rpc_client_call_find_by_id(rpc->client, rpc->StubCallId);

		if (!call)
			goto fail;

		if (call->OpNum != TsProxySetupReceivePipeOpnum)
		{
			const rpcconn_response_hdr_t* response =
			    (const rpcconn_response_hdr_t*)&header.response;
			if (!Stream_EnsureCapacity(pdu->s, response->alloc_hint))
				goto fail;

			if (Stream_Length(fragment) < StubOffset + StubLength)
				goto fail;

			Stream_SetPosition(fragment, StubOffset);
			Stream_Write(pdu->s, Stream_ConstPointer(fragment), StubLength);
			rpc->StubFragCount++;

			if (response->alloc_hint == StubLength)
			{
				pdu->Flags = RPC_PDU_FLAG_STUB;
				pdu->Type = PTYPE_RESPONSE;
				pdu->CallId = rpc->StubCallId;

				if (rpc_client_recv_pdu(rpc, pdu) < 0)
					goto fail;
				rpc_pdu_reset(pdu);
				rpc->StubFragCount = 0;
				rpc->StubCallId = 0;
			}
		}
		else
		{
			const rpcconn_response_hdr_t* response = &header.response;
			if (Stream_Length(fragment) < StubOffset + StubLength)
				goto fail;
			Stream_SetPosition(fragment, StubOffset);
			rpc_client_receive_pipe_write(rpc->client, Stream_ConstPointer(fragment), StubLength);
			rpc->StubFragCount++;

			if (response->alloc_hint == StubLength)
			{
				rpc->StubFragCount = 0;
				rpc->StubCallId = 0;
			}
		}

		goto success;
	}
	else if (header.common.ptype == PTYPE_RTS)
	{
		if (rpc->State < RPC_CLIENT_STATE_CONTEXT_NEGOTIATED)
		{
			pdu->Flags = 0;
			pdu->Type = header.common.ptype;
			pdu->CallId = header.common.call_id;

			const size_t len = Stream_Length(fragment);
			if (!Stream_EnsureCapacity(pdu->s, len))
				goto fail;

			Stream_Write(pdu->s, Stream_Buffer(fragment), len);

			if (rpc_client_recv_pdu(rpc, pdu) < 0)
				goto fail;

			rpc_pdu_reset(pdu);
		}
		else
		{
			if (!rts_recv_out_of_sequence_pdu(rpc, fragment, &header))
				goto fail;
		}

		goto success;
	}
	else if (header.common.ptype == PTYPE_BIND_ACK ||
	         header.common.ptype == PTYPE_ALTER_CONTEXT_RESP)
	{
		pdu->Flags = 0;
		pdu->Type = header.common.ptype;
		pdu->CallId = header.common.call_id;

		const size_t len = Stream_Length(fragment);
		if (!Stream_EnsureCapacity(pdu->s, len))
			goto fail;

		Stream_Write(pdu->s, Stream_Buffer(fragment), len);

		if (rpc_client_recv_pdu(rpc, pdu) < 0)
			goto fail;

		rpc_pdu_reset(pdu);
		goto success;
	}
	else if (header.common.ptype == PTYPE_FAULT)
	{
		const rpcconn_fault_hdr_t* fault = (const rpcconn_fault_hdr_t*)&header.fault;
		rpc_recv_fault_pdu(fault->status);
		goto fail;
	}
	else
	{
		WLog_ERR(TAG, "unexpected RPC PDU type 0x%02" PRIX8 "", header.common.ptype);
		goto fail;
	}

success:
	rc = (rc < 0) ? 1 : 0; /* In case of default error return change to 1, otherwise we already set
	                          the return code */
fail:
	rts_free_pdu_header(&header, FALSE);
	return rc;
}

static SSIZE_T rpc_client_default_out_channel_recv(rdpRpc* rpc)
{
	SSIZE_T status = -1;
	HttpResponse* response = NULL;
	RpcInChannel* inChannel = NULL;
	RpcOutChannel* outChannel = NULL;
	HANDLE outChannelEvent = NULL;
	RpcVirtualConnection* connection = rpc->VirtualConnection;
	inChannel = connection->DefaultInChannel;
	outChannel = connection->DefaultOutChannel;
	BIO_get_event(outChannel->common.tls->bio, &outChannelEvent);

	if (outChannel->State < CLIENT_OUT_CHANNEL_STATE_OPENED)
	{
		if (WaitForSingleObject(outChannelEvent, 0) != WAIT_OBJECT_0)
			return 1;

		response = http_response_recv(outChannel->common.tls, TRUE);

		if (!response)
			return -1;

		if (outChannel->State == CLIENT_OUT_CHANNEL_STATE_SECURITY)
		{
			/* Receive OUT Channel Response */
			if (!rpc_ncacn_http_recv_out_channel_response(&outChannel->common, response))
			{
				http_response_free(response);
				WLog_ERR(TAG, "rpc_ncacn_http_recv_out_channel_response failure");
				return -1;
			}

			/* Send OUT Channel Request */

			if (!rpc_ncacn_http_send_out_channel_request(&outChannel->common, FALSE))
			{
				http_response_free(response);
				WLog_ERR(TAG, "rpc_ncacn_http_send_out_channel_request failure");
				return -1;
			}

			if (rpc_ncacn_http_is_final_request(&outChannel->common))
			{
				rpc_ncacn_http_auth_uninit(&outChannel->common);
				rpc_out_channel_transition_to_state(outChannel,
				                                    CLIENT_OUT_CHANNEL_STATE_NEGOTIATED);

				/* Send CONN/A1 PDU over OUT channel */

				if (!rts_send_CONN_A1_pdu(rpc))
				{
					http_response_free(response);
					WLog_ERR(TAG, "rpc_send_CONN_A1_pdu error!");
					return -1;
				}

				rpc_out_channel_transition_to_state(outChannel, CLIENT_OUT_CHANNEL_STATE_OPENED);

				if (inChannel->State == CLIENT_IN_CHANNEL_STATE_OPENED)
				{
					rpc_virtual_connection_transition_to_state(
					    rpc, connection, VIRTUAL_CONNECTION_STATE_OUT_CHANNEL_WAIT);
				}
			}

			status = 1;
		}

		http_response_free(response);
	}
	else if (connection->State == VIRTUAL_CONNECTION_STATE_OUT_CHANNEL_WAIT)
	{
		/* Receive OUT channel response */
		if (WaitForSingleObject(outChannelEvent, 0) != WAIT_OBJECT_0)
			return 1;

		response = http_response_recv(outChannel->common.tls, FALSE);

		if (!response)
			return -1;

		const INT16 statusCode = http_response_get_status_code(response);

		if (statusCode != HTTP_STATUS_OK)
		{
			http_response_log_error_status(WLog_Get(TAG), WLOG_ERROR, response);

			if (statusCode == HTTP_STATUS_DENIED)
			{
				rdpContext* context = transport_get_context(rpc->transport);
				freerdp_set_last_error_if_not(context, FREERDP_ERROR_CONNECT_ACCESS_DENIED);
			}

			http_response_free(response);
			return -1;
		}

		http_response_free(response);
		rpc_virtual_connection_transition_to_state(rpc, rpc->VirtualConnection,
		                                           VIRTUAL_CONNECTION_STATE_WAIT_A3W);
		status = 1;
	}
	else
	{
		wStream* fragment = rpc->client->ReceiveFragment;

		while (1)
		{
			size_t pos = 0;
			rpcconn_common_hdr_t header = { 0 };

			while (Stream_GetPosition(fragment) < RPC_COMMON_FIELDS_LENGTH)
			{
				status = rpc_channel_read(&outChannel->common, fragment,
				                          RPC_COMMON_FIELDS_LENGTH - Stream_GetPosition(fragment));

				if (status < 0)
					return -1;

				if (Stream_GetPosition(fragment) < RPC_COMMON_FIELDS_LENGTH)
					return 0;
			}

			pos = Stream_GetPosition(fragment);
			Stream_SetPosition(fragment, 0);

			/* Ignore errors, the PDU might not be complete. */
			rts_read_common_pdu_header(fragment, &header, TRUE);
			Stream_SetPosition(fragment, pos);

			if (header.frag_length > rpc->max_recv_frag)
			{
				WLog_ERR(TAG,
				         "rpc_client_recv: invalid fragment size: %" PRIu16 " (max: %" PRIu16 ")",
				         header.frag_length, rpc->max_recv_frag);
				winpr_HexDump(TAG, WLOG_ERROR, Stream_Buffer(fragment),
				              Stream_GetPosition(fragment));
				return -1;
			}

			while (Stream_GetPosition(fragment) < header.frag_length)
			{
				status = rpc_channel_read(&outChannel->common, fragment,
				                          header.frag_length - Stream_GetPosition(fragment));

				if (status < 0)
				{
					WLog_ERR(TAG, "error reading fragment body");
					return -1;
				}

				if (Stream_GetPosition(fragment) < header.frag_length)
					return 0;
			}

			{
				/* complete fragment received */
				status = rpc_client_recv_fragment(rpc, fragment);

				if (status < 0)
					return status;

				/* channel recycling may update channel pointers */
				if (outChannel->State == CLIENT_OUT_CHANNEL_STATE_RECYCLED &&
				    connection->NonDefaultOutChannel)
				{
					rpc_channel_free(&connection->DefaultOutChannel->common);
					connection->DefaultOutChannel = connection->NonDefaultOutChannel;
					connection->NonDefaultOutChannel = NULL;
					rpc_out_channel_transition_to_state(connection->DefaultOutChannel,
					                                    CLIENT_OUT_CHANNEL_STATE_OPENED);
					rpc_virtual_connection_transition_to_state(
					    rpc, connection, VIRTUAL_CONNECTION_STATE_OUT_CHANNEL_WAIT);
					return 0;
				}

				Stream_SetPosition(fragment, 0);
			}
		}
	}

	return status;
}

static SSIZE_T rpc_client_nondefault_out_channel_recv(rdpRpc* rpc)
{
	SSIZE_T status = -1;
	HttpResponse* response = NULL;
	RpcOutChannel* nextOutChannel = NULL;
	HANDLE nextOutChannelEvent = NULL;
	nextOutChannel = rpc->VirtualConnection->NonDefaultOutChannel;
	BIO_get_event(nextOutChannel->common.tls->bio, &nextOutChannelEvent);

	if (WaitForSingleObject(nextOutChannelEvent, 0) != WAIT_OBJECT_0)
		return 1;

	response = http_response_recv(nextOutChannel->common.tls, TRUE);

	if (response)
	{
		switch (nextOutChannel->State)
		{
			case CLIENT_OUT_CHANNEL_STATE_SECURITY:
				if (rpc_ncacn_http_recv_out_channel_response(&nextOutChannel->common, response))
				{
					if (rpc_ncacn_http_send_out_channel_request(&nextOutChannel->common, TRUE))
					{
						if (rpc_ncacn_http_is_final_request(&nextOutChannel->common))
						{
							rpc_ncacn_http_auth_uninit(&nextOutChannel->common);

							if (rts_send_OUT_R1_A3_pdu(rpc))
							{
								status = 1;
								rpc_out_channel_transition_to_state(
								    nextOutChannel, CLIENT_OUT_CHANNEL_STATE_OPENED_A6W);
							}
							else
							{
								WLog_ERR(TAG, "rts_send_OUT_R1/A3_pdu failure");
							}
						}
						else
						{
							status = 1;
						}
					}
					else
					{
						WLog_ERR(TAG, "rpc_ncacn_http_send_out_channel_request failure");
					}
				}
				else
				{
					WLog_ERR(TAG, "rpc_ncacn_http_recv_out_channel_response failure");
				}

				break;

			case CLIENT_OUT_CHANNEL_STATE_INITIAL:
			case CLIENT_OUT_CHANNEL_STATE_CONNECTED:
			case CLIENT_OUT_CHANNEL_STATE_NEGOTIATED:
			default:
				WLog_ERR(TAG,
				         "rpc_client_nondefault_out_channel_recv: Unexpected message %08" PRIx32,
				         nextOutChannel->State);
				status = -1;
		}

		http_response_free(response);
	}

	return status;
}

int rpc_client_out_channel_recv(rdpRpc* rpc)
{
	SSIZE_T status = 0;
	RpcVirtualConnection* connection = rpc->VirtualConnection;

	if (connection->DefaultOutChannel)
	{
		status = rpc_client_default_out_channel_recv(rpc);

		if (status < 0)
			return -1;
	}

	if (connection->NonDefaultOutChannel)
	{
		status = rpc_client_nondefault_out_channel_recv(rpc);

		if (status < 0)
			return -1;
	}

	return 1;
}

int rpc_client_in_channel_recv(rdpRpc* rpc)
{
	int status = 1;
	HttpResponse* response = NULL;
	RpcInChannel* inChannel = NULL;
	RpcOutChannel* outChannel = NULL;
	HANDLE InChannelEvent = NULL;
	RpcVirtualConnection* connection = rpc->VirtualConnection;
	inChannel = connection->DefaultInChannel;
	outChannel = connection->DefaultOutChannel;
	BIO_get_event(inChannel->common.tls->bio, &InChannelEvent);

	if (WaitForSingleObject(InChannelEvent, 0) != WAIT_OBJECT_0)
		return 1;

	if (inChannel->State < CLIENT_IN_CHANNEL_STATE_OPENED)
	{
		response = http_response_recv(inChannel->common.tls, TRUE);

		if (!response)
			return -1;

		if (inChannel->State == CLIENT_IN_CHANNEL_STATE_SECURITY)
		{
			if (!rpc_ncacn_http_recv_in_channel_response(&inChannel->common, response))
			{
				WLog_ERR(TAG, "rpc_ncacn_http_recv_in_channel_response failure");
				http_response_free(response);
				return -1;
			}

			/* Send IN Channel Request */

			if (!rpc_ncacn_http_send_in_channel_request(&inChannel->common))
			{
				WLog_ERR(TAG, "rpc_ncacn_http_send_in_channel_request failure");
				http_response_free(response);
				return -1;
			}

			if (rpc_ncacn_http_is_final_request(&inChannel->common))
			{
				rpc_ncacn_http_auth_uninit(&inChannel->common);
				rpc_in_channel_transition_to_state(inChannel, CLIENT_IN_CHANNEL_STATE_NEGOTIATED);

				/* Send CONN/B1 PDU over IN channel */

				if (!rts_send_CONN_B1_pdu(rpc))
				{
					WLog_ERR(TAG, "rpc_send_CONN_B1_pdu error!");
					http_response_free(response);
					return -1;
				}

				rpc_in_channel_transition_to_state(inChannel, CLIENT_IN_CHANNEL_STATE_OPENED);

				if (outChannel->State == CLIENT_OUT_CHANNEL_STATE_OPENED)
				{
					rpc_virtual_connection_transition_to_state(
					    rpc, connection, VIRTUAL_CONNECTION_STATE_OUT_CHANNEL_WAIT);
				}
			}

			status = 1;
		}

		http_response_free(response);
	}
	else
	{
		response = http_response_recv(inChannel->common.tls, TRUE);

		if (!response)
			return -1;

		/* We can receive an unauthorized HTTP response on the IN channel */
		http_response_free(response);
	}

	return status;
}

/**
 * [MS-RPCE] Client Call:
 * http://msdn.microsoft.com/en-us/library/gg593159/
 */

RpcClientCall* rpc_client_call_find_by_id(RpcClient* client, UINT32 CallId)
{
	RpcClientCall* clientCall = NULL;

	if (!client)
		return NULL;

	ArrayList_Lock(client->ClientCallList);
	const size_t count = ArrayList_Count(client->ClientCallList);

	for (size_t index = 0; index < count; index++)
	{
		clientCall = (RpcClientCall*)ArrayList_GetItem(client->ClientCallList, index);

		if (clientCall->CallId == CallId)
			break;
	}

	ArrayList_Unlock(client->ClientCallList);
	return clientCall;
}

RpcClientCall* rpc_client_call_new(UINT32 CallId, UINT32 OpNum)
{
	RpcClientCall* clientCall = NULL;
	clientCall = (RpcClientCall*)calloc(1, sizeof(RpcClientCall));

	if (!clientCall)
		return NULL;

	clientCall->CallId = CallId;
	clientCall->OpNum = OpNum;
	clientCall->State = RPC_CLIENT_CALL_STATE_SEND_PDUS;
	return clientCall;
}

void rpc_client_call_free(RpcClientCall* clientCall)
{
	free(clientCall);
}

static void rpc_array_client_call_free(void* call)
{
	rpc_client_call_free((RpcClientCall*)call);
}

int rpc_in_channel_send_pdu(RpcInChannel* inChannel, const BYTE* buffer, size_t length)
{
	SSIZE_T status = 0;
	RpcClientCall* clientCall = NULL;
	wStream s;
	rpcconn_common_hdr_t header = { 0 };

	status = rpc_channel_write(&inChannel->common, buffer, length);

	if (status <= 0)
		return -1;

	Stream_StaticConstInit(&s, buffer, length);
	if (!rts_read_common_pdu_header(&s, &header, FALSE))
		return -1;

	clientCall = rpc_client_call_find_by_id(inChannel->common.client, header.call_id);
	if (!clientCall)
		return -1;

	clientCall->State = RPC_CLIENT_CALL_STATE_DISPATCHED;

	/*
	 * This protocol specifies that only RPC PDUs are subject to the flow control abstract
	 * data model. RTS PDUs and the HTTP request and response headers are not subject to flow
	 * control. Implementations of this protocol MUST NOT include them when computing any of the
	 * variables specified by this abstract data model.
	 */

	if (header.ptype == PTYPE_REQUEST)
	{
		const uint32_t ustatus = WINPR_ASSERTING_INT_CAST(uint32_t, status);
		inChannel->BytesSent += ustatus;
		inChannel->SenderAvailableWindow -= ustatus;
	}

	if (status > INT32_MAX)
		return -1;
	return (int)status;
}

BOOL rpc_client_write_call(rdpRpc* rpc, wStream* s, UINT16 opnum)
{
	size_t offset = 0;
	BYTE* buffer = NULL;
	size_t stub_data_pad = 0;
	SecBuffer plaintext;
	SecBuffer ciphertext = { 0 };
	RpcClientCall* clientCall = NULL;
	rdpCredsspAuth* auth = NULL;
	rpcconn_request_hdr_t request_pdu = { 0 };
	RpcVirtualConnection* connection = NULL;
	RpcInChannel* inChannel = NULL;
	BOOL rc = FALSE;

	if (!s)
		return FALSE;

	if (!rpc)
		goto fail;

	auth = rpc->auth;
	connection = rpc->VirtualConnection;

	if (!auth)
	{
		WLog_ERR(TAG, "invalid auth context");
		goto fail;
	}

	if (!connection)
		goto fail;

	inChannel = connection->DefaultInChannel;

	if (!inChannel)
		goto fail;

	Stream_SealLength(s);
	const size_t length = Stream_Length(s);
	if (length > UINT32_MAX)
		goto fail;

	const size_t asize = credssp_auth_trailer_size(auth);

	request_pdu.header = rpc_pdu_header_init(rpc);
	request_pdu.header.ptype = PTYPE_REQUEST;
	request_pdu.header.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG;
	request_pdu.header.auth_length = (UINT16)asize;
	request_pdu.header.call_id = rpc->CallId++;
	request_pdu.alloc_hint = (UINT32)length;
	request_pdu.p_cont_id = 0x0000;
	request_pdu.opnum = opnum;
	clientCall = rpc_client_call_new(request_pdu.header.call_id, request_pdu.opnum);

	if (!clientCall)
		goto fail;

	if (!ArrayList_Append(rpc->client->ClientCallList, clientCall))
	{
		rpc_client_call_free(clientCall);
		goto fail;
	}

	// NOLINTNEXTLINE(clang-analyzer-unix.Malloc): ArrayList_Append takes ownership of clientCall
	if (request_pdu.opnum == TsProxySetupReceivePipeOpnum)
		rpc->PipeCallId = request_pdu.header.call_id;

	request_pdu.stub_data = Stream_Buffer(s);
	offset = 24;
	stub_data_pad = rpc_offset_align(&offset, 8);
	offset += length;

	const size_t alg = rpc_offset_align(&offset, 4);
	WINPR_ASSERT(alg <= UINT8_MAX);
	request_pdu.auth_verifier.auth_pad_length = (UINT8)alg;
	request_pdu.auth_verifier.auth_type =
	    rpc_auth_pkg_to_security_provider(credssp_auth_pkg_name(rpc->auth));
	request_pdu.auth_verifier.auth_level = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY;
	request_pdu.auth_verifier.auth_reserved = 0x00;
	request_pdu.auth_verifier.auth_context_id = 0x00000000;
	offset += (8 + request_pdu.header.auth_length);

	if (offset > UINT16_MAX)
		goto fail;
	request_pdu.header.frag_length = (UINT16)offset;
	buffer = (BYTE*)calloc(1, request_pdu.header.frag_length);

	if (!buffer)
		goto fail;

	CopyMemory(buffer, &request_pdu, 24);
	offset = 24;
	rpc_offset_pad(&offset, stub_data_pad);
	CopyMemory(&buffer[offset], request_pdu.stub_data, length);
	offset += length;
	rpc_offset_pad(&offset, request_pdu.auth_verifier.auth_pad_length);
	CopyMemory(&buffer[offset], &request_pdu.auth_verifier.auth_type, 8);
	offset += 8;

	if (offset > request_pdu.header.frag_length)
		goto fail;

	plaintext.pvBuffer = buffer;
	plaintext.cbBuffer = (UINT32)offset;
	plaintext.BufferType = SECBUFFER_READONLY;

	size_t size = 0;
	if (!credssp_auth_encrypt(auth, &plaintext, &ciphertext, &size, rpc->SendSeqNum++))
		goto fail;

	if (offset + size > request_pdu.header.frag_length)
	{
		sspi_SecBufferFree(&ciphertext);
		goto fail;
	}

	CopyMemory(&buffer[offset], ciphertext.pvBuffer, size);
	offset += size;

	sspi_SecBufferFree(&ciphertext);

	if (rpc_in_channel_send_pdu(inChannel, buffer, request_pdu.header.frag_length) < 0)
		goto fail;

	rc = TRUE;
fail:
	free(buffer);
	Stream_Free(s, TRUE);
	return rc;
}

static BOOL rpc_client_resolve_gateway(rdpSettings* settings, char** host, UINT16* port,
                                       BOOL* isProxy)
{
	struct addrinfo* result = NULL;

	if (!settings || !host || !port || !isProxy)
		return FALSE;
	else
	{
		const char* peerHostname = freerdp_settings_get_string(settings, FreeRDP_GatewayHostname);
		const char* proxyUsername = freerdp_settings_get_string(settings, FreeRDP_GatewayUsername);
		const char* proxyPassword = freerdp_settings_get_string(settings, FreeRDP_GatewayPassword);
		*port = (UINT16)freerdp_settings_get_uint32(settings, FreeRDP_GatewayPort);
		*isProxy = proxy_prepare(settings, &peerHostname, port, &proxyUsername, &proxyPassword);
		result = freerdp_tcp_resolve_host(peerHostname, *port, 0);

		if (!result)
			return FALSE;

		*host =
		    freerdp_tcp_address_to_string((const struct sockaddr_storage*)result->ai_addr, NULL);
		freeaddrinfo(result);
		return TRUE;
	}
}

RpcClient* rpc_client_new(rdpContext* context, UINT32 max_recv_frag)
{
	wObject* obj = NULL;
	RpcClient* client = (RpcClient*)calloc(1, sizeof(RpcClient));

	if (!client)
		return NULL;

	if (!rpc_client_resolve_gateway(context->settings, &client->host, &client->port,
	                                &client->isProxy))
		goto fail;

	client->context = context;

	if (!client->context)
		goto fail;

	client->pdu = rpc_pdu_new();

	if (!client->pdu)
		goto fail;

	client->ReceiveFragment = Stream_New(NULL, max_recv_frag);

	if (!client->ReceiveFragment)
		goto fail;

	client->PipeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (!client->PipeEvent)
		goto fail;

	if (!ringbuffer_init(&(client->ReceivePipe), 4096))
		goto fail;

	if (!InitializeCriticalSectionAndSpinCount(&(client->PipeLock), 4000))
		goto fail;

	client->ClientCallList = ArrayList_New(TRUE);

	if (!client->ClientCallList)
		goto fail;

	obj = ArrayList_Object(client->ClientCallList);
	obj->fnObjectFree = rpc_array_client_call_free;
	return client;
fail:
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_MISMATCHED_DEALLOC
	rpc_client_free(client);
	WINPR_PRAGMA_DIAG_POP
	return NULL;
}

void rpc_client_free(RpcClient* client)
{
	if (!client)
		return;

	free(client->host);

	if (client->ReceiveFragment)
		Stream_Free(client->ReceiveFragment, TRUE);

	if (client->PipeEvent)
		(void)CloseHandle(client->PipeEvent);

	ringbuffer_destroy(&(client->ReceivePipe));
	DeleteCriticalSection(&(client->PipeLock));

	if (client->pdu)
		rpc_pdu_free(client->pdu);

	if (client->ClientCallList)
		ArrayList_Free(client->ClientCallList);

	free(client);
}
