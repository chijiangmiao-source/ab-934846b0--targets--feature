// 规范 JSON（TUF/OLPC 风格）与严格解析。
// 规范形式：对象字段名按 Unicode 码点升序、无任何空白、UTF-8 输出前的字符串形式。
// 严格解析：任何层级出现重复对象名即拒绝（JSON.parse 会静默覆盖，必须自行解析）。

export class MetadataParseError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'MetadataParseError';
    this.code = code;
    Object.assign(this, details);
  }
}

// 按 Unicode 码点比较（JS 默认 sort 按 UTF-16 码元，代理对会排错）
export function compareKeyCodePoints(a, b) {
  const ac = [...a];
  const bc = [...b];
  const n = Math.min(ac.length, bc.length);
  for (let i = 0; i < n; i++) {
    const d = ac[i].codePointAt(0) - bc[i].codePointAt(0);
    if (d !== 0) return d;
  }
  return ac.length - bc.length;
}

export function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) {
        throw new Error(`无法规范化的数字：${value}（仅支持安全整数）`);
      }
      return String(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map((item) => canonicalize(item)).join(',') + ']';
      }
      const keys = Object.keys(value).sort(compareKeyCodePoints);
      let out = '{';
      for (let i = 0; i < keys.length; i++) {
        if (i > 0) out += ',';
        out += JSON.stringify(keys[i]) + ':' + canonicalize(value[keys[i]]);
      }
      return out + '}';
    }
    default:
      throw new Error(`无法规范化的类型：${typeof value}`);
  }
}

const MAX_DEPTH = 100;

export function parseJsonStrict(text) {
  if (typeof text !== 'string') {
    throw new MetadataParseError('INVALID_JSON', '输入必须是字符串');
  }
  let pos = 0;
  let depth = 0;
  const len = text.length;

  const fail = (msg) => {
    throw new MetadataParseError('INVALID_JSON', `${msg}（偏移 ${pos}）`);
  };

  function skipWs() {
    while (pos < len) {
      const c = text.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos++;
      else break;
    }
  }

  function expectLiteral(lit) {
    if (text.startsWith(lit, pos)) pos += lit.length;
    else fail('无效字面值');
  }

  function parseString() {
    pos++; // 跳过开引号
    let out = '';
    for (;;) {
      if (pos >= len) fail('字符串未闭合');
      const c = text[pos];
      if (c === '"') {
        pos++;
        return out;
      }
      if (c === '\\') {
        pos++;
        const e = text[pos];
        switch (e) {
          case '"': out += '"'; pos++; break;
          case '\\': out += '\\'; pos++; break;
          case '/': out += '/'; pos++; break;
          case 'b': out += '\b'; pos++; break;
          case 'f': out += '\f'; pos++; break;
          case 'n': out += '\n'; pos++; break;
          case 'r': out += '\r'; pos++; break;
          case 't': out += '\t'; pos++; break;
          case 'u': {
            const hex = text.substr(pos + 1, 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('无效的 \\u 转义');
            out += String.fromCharCode(parseInt(hex, 16));
            pos += 5;
            break;
          }
          default:
            fail('无效转义序列');
        }
        continue;
      }
      if (text.charCodeAt(pos) < 0x20) fail('字符串含未转义控制字符');
      out += c;
      pos++;
    }
  }

  function parseNumber() {
    const start = pos;
    if (text[pos] === '-') pos++;
    if (text[pos] === '0') {
      pos++;
    } else if (text[pos] >= '1' && text[pos] <= '9') {
      while (text[pos] >= '0' && text[pos] <= '9') pos++;
    } else {
      fail('无效数字');
    }
    if (text[pos] === '.') {
      pos++;
      if (!(text[pos] >= '0' && text[pos] <= '9')) fail('无效数字');
      while (text[pos] >= '0' && text[pos] <= '9') pos++;
    }
    if (text[pos] === 'e' || text[pos] === 'E') {
      pos++;
      if (text[pos] === '+' || text[pos] === '-') pos++;
      if (!(text[pos] >= '0' && text[pos] <= '9')) fail('无效数字');
      while (text[pos] >= '0' && text[pos] <= '9') pos++;
    }
    return Number(text.slice(start, pos));
  }

  function parseObject() {
    pos++; // 跳过 {
    const obj = {};
    const seen = new Set();
    skipWs();
    if (text[pos] === '}') {
      pos++;
      return obj;
    }
    for (;;) {
      skipWs();
      if (text[pos] !== '"') fail('对象键必须是字符串');
      const key = parseString();
      if (seen.has(key)) {
        throw new MetadataParseError(
          'DUPLICATE_OBJECT_NAME',
          `重复对象名：${JSON.stringify(key)}`,
          { key }
        );
      }
      seen.add(key);
      skipWs();
      if (text[pos] !== ':') fail("对象键后期望 ':'");
      pos++;
      obj[key] = parseValue();
      skipWs();
      const c = text[pos];
      if (c === ',') {
        pos++;
        continue;
      }
      if (c === '}') {
        pos++;
        return obj;
      }
      fail("对象项后期望 ',' 或 '}'");
    }
  }

  function parseArray() {
    pos++; // 跳过 [
    const arr = [];
    skipWs();
    if (text[pos] === ']') {
      pos++;
      return arr;
    }
    for (;;) {
      arr.push(parseValue());
      skipWs();
      const c = text[pos];
      if (c === ',') {
        pos++;
        continue;
      }
      if (c === ']') {
        pos++;
        return arr;
      }
      fail("数组元素后期望 ',' 或 ']'");
    }
  }

  function parseValue() {
    if (++depth > MAX_DEPTH) fail('嵌套过深');
    skipWs();
    if (pos >= len) fail('输入意外结束');
    const c = text[pos];
    let value;
    if (c === '{') value = parseObject();
    else if (c === '[') value = parseArray();
    else if (c === '"') value = parseString();
    else if (c === 't') { expectLiteral('true'); value = true; }
    else if (c === 'f') { expectLiteral('false'); value = false; }
    else if (c === 'n') { expectLiteral('null'); value = null; }
    else if (c === '-' || (c >= '0' && c <= '9')) value = parseNumber();
    else fail(`无法识别的字符 ${JSON.stringify(c)}`);
    depth--;
    return value;
  }

  skipWs();
  const value = parseValue();
  skipWs();
  if (pos !== len) fail('JSON 末尾存在多余内容');
  return value;
}
