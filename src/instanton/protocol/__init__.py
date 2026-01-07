"""Instanton Protocol - Wire protocol definitions with compression and streaming."""

from .messages import (
    CHUNK_SIZE,
    MAGIC,
    MAX_MESSAGE_SIZE,
    MESSAGE_TYPES,
    MIN_COMPRESSION_SIZE,
    PROTOCOL_VERSION,
    AllMessages,
    ChunkAck,
    ChunkAssembler,
    ChunkData,
    ChunkEnd,
    ChunkStart,
    ClientMessage,
    CompressionType,
    ConnectRequest,
    ConnectResponse,
    Disconnect,
    ErrorCode,
    HttpRequest,
    HttpResponse,
    NegotiateRequest,
    NegotiateResponse,
    Ping,
    Pong,
    ProtocolNegotiator,
    ServerMessage,
    compress_data,
    create_chunks,
    decode_message,
    decompress_data,
    encode_message,
    parse_message,
)

__all__ = [
    # Constants
    "PROTOCOL_VERSION",
    "MAGIC",
    "MAX_MESSAGE_SIZE",
    "CHUNK_SIZE",
    "MIN_COMPRESSION_SIZE",
    # Enums
    "ErrorCode",
    "CompressionType",
    # Negotiation messages
    "NegotiateRequest",
    "NegotiateResponse",
    # Union types
    "ClientMessage",
    "ServerMessage",
    "AllMessages",
    # Connection messages
    "ConnectRequest",
    "ConnectResponse",
    # HTTP messages
    "HttpRequest",
    "HttpResponse",
    # Streaming messages
    "ChunkStart",
    "ChunkData",
    "ChunkEnd",
    "ChunkAck",
    # Keep-alive messages
    "Ping",
    "Pong",
    "Disconnect",
    # Functions
    "encode_message",
    "decode_message",
    "parse_message",
    "compress_data",
    "decompress_data",
    "create_chunks",
    # Classes
    "ChunkAssembler",
    "ProtocolNegotiator",
    "MESSAGE_TYPES",
]
