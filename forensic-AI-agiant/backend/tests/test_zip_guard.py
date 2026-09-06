import io
import zipfile

import pytest

from parser import ZipGuardError, extract_text


class _FakeUploadFile:
    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self._content = content

    async def read(self):
        return self._content


def _zip_with_n_files(n: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(n):
            z.writestr(f"file{i}.txt", "x")
    return buf.getvalue()


@pytest.mark.asyncio
async def test_too_many_files_is_rejected():
    content = _zip_with_n_files(201)
    with pytest.raises(ZipGuardError):
        await extract_text(_FakeUploadFile("bomb.zip", content))


@pytest.mark.asyncio
async def test_oversized_single_file_is_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # 21MB of highly-compressible zeros — small on disk, huge decompressed.
        z.writestr("huge.txt", b"0" * (21 * 1024 * 1024))
    with pytest.raises(ZipGuardError):
        await extract_text(_FakeUploadFile("bomb.zip", buf.getvalue()))


@pytest.mark.asyncio
async def test_high_compression_ratio_is_rejected_as_likely_bomb():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Small compressed size, huge uncompressed size => bomb-like ratio,
        # but still under the absolute per-file/total-size caps on their own.
        z.writestr("ratio.txt", b"A" * (5 * 1024 * 1024))
    with pytest.raises(ZipGuardError):
        await extract_text(_FakeUploadFile("bomb.zip", buf.getvalue()))


@pytest.mark.asyncio
async def test_normal_small_zip_is_accepted():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("notes.txt", "just a normal small text file")
    text, eml_data = await extract_text(_FakeUploadFile("evidence.zip", buf.getvalue()))
    assert "just a normal small text file" in text
    assert eml_data is None


@pytest.mark.asyncio
async def test_zip_containing_eml_is_parsed(fixtures_dir):
    eml_bytes = (fixtures_dir / "typosquat_phishing.eml").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("evidence.eml", eml_bytes)
    text, eml_data = await extract_text(_FakeUploadFile("case.zip", buf.getvalue()))
    assert eml_data is not None
    assert eml_data["auth_results"]["spf"] == "fail"
