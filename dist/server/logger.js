const SEVERITY = { info: 'INFO', warn: 'WARNING', error: 'ERROR' };
export function log(level, message, fields = {}) {
    if (process.env.NODE_ENV === 'test')
        return;
    const line = JSON.stringify({ severity: SEVERITY[level], message, ...fields });
    if (level === 'info')
        console.log(line);
    else
        console.error(line);
}
