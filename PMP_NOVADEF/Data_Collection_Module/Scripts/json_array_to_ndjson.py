#!/usr/bin/env python3
import sys, json

def iter_json_objects_from_array_stream(stream):
    """
    Collects network packets in JSON format and exports them in NDJSON format (one JSON object per line).
    """
    buf = []
    depth = 0
    in_string = False
    escape = False
    started = False

    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        for ch in chunk:
            if isinstance(ch, int):
                ch = chr(ch)
            buf.append(ch)

            c = ch
            if in_string:
                if escape:
                    escape = False
                elif c == '\\':
                    escape = True
                elif c == '"':
                    in_string = False
                continue
            else:
                if c == '"':
                    in_string = True
                    continue
                if c == '{':
                    depth += 1
                    started = True
                elif c == '}':
                    depth -= 1

            # When closing the object ({}), emit a line
            if started and depth == 0:
                obj_text = ''.join(buf).strip()
                l = obj_text.find('{')
                r = obj_text.rfind('}')
                if l != -1 and r != -1 and r > l:
                    obj_text = obj_text[l:r+1]
                    try:
                        obj = json.loads(obj_text)
                        yield obj
                    except Exception:
                        pass
                buf = []
                started = False

if __name__ == "__main__":
    for obj in iter_json_objects_from_array_stream(sys.stdin):
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        sys.stdout.flush()
