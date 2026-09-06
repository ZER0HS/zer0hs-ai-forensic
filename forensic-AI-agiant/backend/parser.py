import zipfile
import io
from header_parser import parse_eml

# Guards against a zip-bomb DoS: a small archive that decompresses into
# something huge (or into thousands of files) and hangs/crashes the server
# during extraction. Checked against the archive's own metadata *before* any
# file is decompressed.
MAX_ZIP_FILE_COUNT          = 200
MAX_ZIP_TOTAL_UNCOMPRESSED  = 50 * 1024 * 1024   # 50 MB combined
MAX_ZIP_SINGLE_FILE         = 20 * 1024 * 1024   # 20 MB per file
MAX_ZIP_COMPRESSION_RATIO   = 100                # uncompressed/compressed


class ZipGuardError(ValueError):
    """Raised when an uploaded zip trips one of the anti-zip-bomb limits."""


def _check_zip_is_safe(z: zipfile.ZipFile) -> None:
    infos = z.infolist()

    if len(infos) > MAX_ZIP_FILE_COUNT:
        raise ZipGuardError(
            f"Zip contains {len(infos)} files — max {MAX_ZIP_FILE_COUNT} allowed."
        )

    total_uncompressed = sum(i.file_size for i in infos)
    if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED:
        raise ZipGuardError(
            f"Zip's uncompressed size ({total_uncompressed} bytes) exceeds "
            f"the {MAX_ZIP_TOTAL_UNCOMPRESSED} byte limit."
        )

    for info in infos:
        if info.file_size > MAX_ZIP_SINGLE_FILE:
            raise ZipGuardError(
                f"'{info.filename}' ({info.file_size} bytes) exceeds the "
                f"{MAX_ZIP_SINGLE_FILE} byte per-file limit."
            )
        if info.compress_size > 0:
            ratio = info.file_size / info.compress_size
            if ratio > MAX_ZIP_COMPRESSION_RATIO:
                raise ZipGuardError(
                    f"'{info.filename}' has a {ratio:.0f}x compression ratio "
                    "— rejected as a likely zip bomb."
                )


async def extract_text(file) -> tuple:
    """Returns (raw_text, eml_data or None). Raises ZipGuardError if an
    uploaded zip trips the anti-zip-bomb limits above."""
    content = await file.read()
    name    = file.filename.lower()

    if name.endswith(".zip"):
        texts    = []
        eml_data = None
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            _check_zip_is_safe(z)
            for fname in z.namelist():
                file_content = z.read(fname)
                if fname.endswith(".eml"):
                    eml_data = parse_eml(file_content)
                    texts.append(eml_data.get("body_text",""))
                elif fname.endswith((".txt",".log",".csv")):
                    texts.append(file_content.decode("utf-8", errors="ignore"))
        return "\n\n".join(texts), eml_data

    elif name.endswith(".eml"):
        eml_data = parse_eml(content)
        full_text = f"""
From: {eml_data['from']}
To: {eml_data['to']}
Subject: {eml_data['subject']}
Date: {eml_data['date']}
Reply-To: {eml_data['reply_to']}
SPF: {eml_data['auth_results']['spf']}
DKIM: {eml_data['auth_results']['dkim']}
DMARC: {eml_data['auth_results']['dmarc']}
Routing IPs: {', '.join(eml_data['routing_ips'])}

{eml_data['body_text']}
"""
        return full_text, eml_data
    else:
        return content.decode("utf-8", errors="ignore"), None
