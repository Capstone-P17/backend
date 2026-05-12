from __future__ import annotations

from fastapi import HTTPException, UploadFile, status

_READ_CHUNK_BYTES = 1024 * 1024


async def read_upload_with_limit(file: UploadFile, *, max_bytes: int) -> bytes:
    content = bytearray()

    while chunk := await file.read(_READ_CHUNK_BYTES):
        content.extend(chunk)
        if len(content) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"업로드 크기는 최대 {max_bytes // (1024 * 1024)}MB까지 허용됩니다",
            )

    return bytes(content)
