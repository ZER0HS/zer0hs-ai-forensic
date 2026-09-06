import zipfile
import io
from header_parser import parse_eml

async def extract_text(file) -> tuple:
    """Returns (raw_text, eml_data or None)"""
    content = await file.read()
    name    = file.filename.lower()

    if name.endswith(".zip"):
        texts   = []
        eml_data = None
        with zipfile.ZipFile(io.BytesIO(content)) as z:
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