import re

# Sources: locations where attacker-controllable data enters the DOM
SOURCES = re.compile(
    r'\b(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer)'
    r'|location\.(?:href|search|hash|pathname)'
    r'|window\.name'
    r'|(?:local|session)Storage(?:\.[A-Za-z_$][\w$]*|\[[^\]]*\])'
    r'|history\.(?:pushState|replaceState))\b')

# Sinks: locations where tainted data can lead to XSS
SINKS = re.compile(
    r'(?:\beval\s*\(|\bexecScript\s*\(|\bsetTimeout\s*\(|\bsetInterval\s*\('
    r'|\bsetImmediate\s*\(|\bFunction\s*\('
    r'|document\.write(?:ln)?\s*\('
    r'|\.innerHTML\b|\.outerHTML\b|\.srcdoc\b'
    r'|insertAdjacentHTML\s*\('
    r'|createContextualFragment\s*\('
    r'|location\.(?:assign|replace)\s*\()')

# message event handlers: window.addEventListener('message', fn) / window.onmessage = fn
HANDLER = re.compile(
    r'addEventListener\(\s*[\'"]message[\'"]\s*,\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)'
    r'|onmessage\s*=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)')

ASSIGN = re.compile(
    r'(?:\b(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*([^;]+)')


def extract_scripts(response):
    """Returns a list of (script_body, line_offset) for every inline script."""
    scripts = []
    for match in re.finditer(r'(?is)<script[^>]*>(.*?)</script>', response):
        offset = response[:match.start(1)].count('\n')
        scripts.append((match.group(1), offset))
    return scripts


def _extract_handler_bodies(script):
    """Yields (param_name, body, body_start_line) for each message handler."""
    for match in HANDLER.finditer(script):
        param = match.group(1) or match.group(2)
        brace = script.find('{', match.end())
        if brace == -1:
            continue
        depth = 0
        for i in range(brace, len(script)):
            if script[i] == '{':
                depth += 1
            elif script[i] == '}':
                depth -= 1
                if depth == 0:
                    body = script[brace + 1:i]
                    start_line = script[:brace].count('\n') + 1
                    yield param, body, start_line
                    break


def classify_origin_check(body, param):
    """Classifies the origin validation of a message handler.

    Returns 'strict', 'weak' or 'none'.
    """
    origin = re.escape(param) + r'\s*\.\s*origin\b'
    if not re.search(origin, body):
        return 'none'
    # strict: strict (in)equality against a literal, or membership in a literal allowlist
    if re.search(origin + r'\s*(?:!==|===|!=|==)', body):
        return 'strict'
    if re.search(r'(?:!==|===|!=|==)[^;]*' + origin, body):
        return 'strict'
    if re.search(r'\[[^\]]*\]\s*\.\s*includes\(\s*' + re.escape(param) + r'\s*\.\s*origin', body):
        return 'strict'
    # anything else (indexOf/includes/startsWith/match/test on the origin string) is bypassable
    return 'weak'


def _tainted_vars(lines, extra_sources):
    """Propagates taint through simple assignments, line by line.

    extra_sources: list of regexes matching additional tainted expressions
    (e.g. event.data inside a message handler).
    Returns a dict {line_number: set(tainted_vars_on_that_line)}.
    """
    tainted = set()
    flow = {}
    for num, line in enumerate(lines, 1):
        for match in ASSIGN.finditer(line):
            var, rhs = match.group(1), match.group(2)
            if var in ('var', 'let', 'const', 'return', 'function'):
                continue
            rhs_tainted = bool(SOURCES.search(rhs))
            rhs_tainted = rhs_tainted or any(src.search(rhs) for src in extra_sources)
            rhs_tainted = rhs_tainted or any(
                re.search(r'\b%s\b' % re.escape(t), rhs) for t in tainted)
            if rhs_tainted:
                tainted.add(var)
        flow[num] = set(tainted)
    return flow


def _line_has_taint(line, tainted, extra_sources):
    if SOURCES.search(line):
        return True
    if any(src.search(line) for src in extra_sources):
        return True
    return any(re.search(r'\b%s\b' % re.escape(t), line) for t in tainted)


def _scan_lines(lines, extra_sources, base_offset, ftype, source_name):
    """Finds source -> sink flows in a list of lines. Returns findings."""
    findings = []
    flow = _tainted_vars(lines, extra_sources)
    for num, line in enumerate(lines, 1):
        for sink in SINKS.finditer(line):
            if _line_has_taint(line, flow[num], extra_sources):
                findings.append({
                    'type': ftype,
                    'source': source_name,
                    'sink': sink.group(0).rstrip('(').strip(),
                    'line': base_offset + num,
                    'snippet': line.strip()[:120],
                })
    return findings


def scan_dom(response):
    """Scans an HTTP response body for DOM-based XSS.

    Returns a list of structured findings:
    {'type', 'source', 'sink', 'line', 'snippet', 'severity', ...}
    """
    findings = []
    for script, offset in extract_scripts(response):
        lines = script.split('\n')
        # generic DOM sources (location.hash, document.URL, ...) -> sinks
        findings.extend(_scan_lines(lines, [], offset, 'dom-xss', 'dom-source'))
        # postMessage handlers
        for param, body, start_line in _extract_handler_bodies(script):
            origin_check = classify_origin_check(body, param)
            data_expr = re.compile(r'\b%s\s*\.\s*data\b' % re.escape(param))
            body_lines = body.split('\n')
            flows = _scan_lines(body_lines, [data_expr], offset + start_line,
                                'postmessage-xss', '%s.data' % param)
            for finding in flows:
                finding['origin_check'] = origin_check
                finding['severity'] = {'none': 'high', 'weak': 'medium',
                                       'strict': 'low'}[origin_check]
            findings.extend(flows)
            data_used = any(data_expr.search(line) for line in body_lines) or flows
            if not flows and data_used and origin_check != 'strict':
                findings.append({
                    'type': 'postmessage-no-origin-check',
                    'source': '%s.data' % param,
                    'sink': None,
                    'line': offset + start_line,
                    'snippet': body_lines[0].strip()[:120] if body_lines else '',
                    'origin_check': origin_check,
                    'severity': 'medium' if origin_check == 'none' else 'low',
                })
    for finding in findings:
        finding.setdefault('severity', 'high')
    # deduplicate
    seen, unique = set(), []
    for finding in findings:
        key = (finding['type'], finding['line'], finding['sink'])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def is_vulnerable(response):
    """True if any exploitable DOM XSS flow was found."""
    return any(f['type'] in ('dom-xss', 'postmessage-xss') for f in scan_dom(response))
