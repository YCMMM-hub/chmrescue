import {
  import_buffer,
  init_browser_buffer
} from "./chunk-KMNLRCGW.mjs";

// src/browser.ts
init_browser_buffer();

// src/reader/chm-archive.ts
init_browser_buffer();

// src/core/parser/chm-parser.ts
init_browser_buffer();

// src/utils/io/bit-reader.ts
init_browser_buffer();
var BitReader = class {
  constructor(buffer) {
    this.buffer = buffer;
    this.position = 0;
    this.bitPosition = 0;
  }
  /**
   * 读取指定位数的数据
   * @param bits 要读取的位数
   * @returns 读取的数值
   */
  read(bits) {
    if (!Number.isInteger(bits) || bits <= 0 || bits > 32) {
      throw new Error(
        "Invalid bits count: must be an integer between 1 and 32"
      );
    }
    if (bits > (this.buffer.length - this.position) * 8 - this.bitPosition) {
      throw new Error("End of buffer reached");
    }
    let result = 0;
    let bitsLeft = bits;
    while (bitsLeft > 0) {
      if (this.position >= this.buffer.length) {
        throw new Error("End of buffer reached");
      }
      const currentByte = this.buffer[this.position];
      const availableBits = 8 - this.bitPosition;
      const bitsToRead = Math.min(bitsLeft, availableBits);
      const mask = (1 << bitsToRead) - 1;
      const shift = availableBits - bitsToRead;
      const extractedBits = currentByte >> shift & mask;
      result = result << bitsToRead | extractedBits;
      this.bitPosition += bitsToRead;
      if (this.bitPosition >= 8) {
        this.position++;
        this.bitPosition = 0;
      }
      bitsLeft -= bitsToRead;
    }
    return result >>> 0;
  }
  /**
   * 预览指定位数的数据（不改变位置）
   * @param bits 要预览的位数
   * @returns 预览的数值
   */
  peek(bits) {
    const currentPosition = this.position;
    const currentBitPosition = this.bitPosition;
    try {
      return this.read(bits);
    } finally {
      this.position = currentPosition;
      this.bitPosition = currentBitPosition;
    }
  }
  /**
   * 跳过指定位数
   * @param bits 要跳过的位数
   */
  skip(bits) {
    if (!Number.isSafeInteger(bits) || bits < 0) {
      throw new Error(
        "Invalid bits count: must be a non-negative safe integer"
      );
    }
    if (bits > (this.buffer.length - this.position) * 8 - this.bitPosition) {
      throw new Error("End of buffer reached");
    }
    const totalBits = this.bitPosition + bits;
    this.position += Math.floor(totalBits / 8);
    this.bitPosition = totalBits % 8;
  }
  /**
   * 对齐到字节边界
   */
  align() {
    if (this.bitPosition > 0) {
      this.position++;
      this.bitPosition = 0;
    }
  }
  /**
   * 检查是否还有更多数据
   * @returns 是否还有数据
   */
  hasMore() {
    return this.position < this.buffer.length;
  }
  /**
   * 获取当前位置信息
   * @returns 位置信息
   */
  getPosition() {
    return {
      byte: this.position,
      bit: this.bitPosition
    };
  }
  /**
   * 设置位置
   * @param byte 字节位置
   * @param bit 位位置
   */
  setPosition(byte, bit = 0) {
    if (!Number.isSafeInteger(byte) || byte < 0 || byte > this.buffer.length) {
      throw new Error("Invalid byte position");
    }
    if (!Number.isInteger(bit) || bit < 0 || bit >= 8 || byte === this.buffer.length && bit !== 0) {
      throw new Error("Invalid bit position");
    }
    this.position = byte;
    this.bitPosition = bit;
  }
  /**
   * 获取剩余字节数
   * @returns 剩余字节数
   */
  remainingBytes() {
    return this.buffer.length - this.position;
  }
};

// src/core/headers/itsf-header.ts
init_browser_buffer();

// src/core/headers/binary.ts
init_browser_buffer();
function isUInt(value) {
  return Number.isSafeInteger(value) && value >= 0;
}
function checkedEnd(offset, length, label) {
  if (!isUInt(offset) || !isUInt(length) || length > Number.MAX_SAFE_INTEGER - offset) {
    throw new Error(`${label}: invalid or unsafe range`);
  }
  return offset + length;
}
function requireRange(buffer, offset, length, label) {
  if (checkedEnd(offset, length, label) > buffer.length) {
    throw new Error(`${label}: truncated or out of bounds`);
  }
}
function readBytes(reader, length, label) {
  if (reader.bitPosition !== 0)
    throw new Error(`${label}: expected byte alignment`);
  requireRange(reader.buffer, reader.position, length, label);
  const start = reader.position;
  reader.setPosition(start + length, 0);
  return reader.buffer.subarray(start, start + length);
}
function readUInt64LE(buffer, offset, label) {
  requireRange(buffer, offset, 8, label);
  const low = buffer.readUInt32LE(offset);
  const high = buffer.readUInt32LE(offset + 4);
  if (high > 2097151)
    throw new Error(`${label}: uint64 exceeds safe integer range`);
  return high * 4294967296 + low;
}

// src/core/headers/itsf-header.ts
var GUIDS = import_buffer.Buffer.from(
  "10fd017caa7bd0119e0c00a0c922e6ec11fd017caa7bd0119e0c00a0c922e6ec",
  "hex"
);
var FPC_V3_GUIDS = import_buffer.Buffer.from(
  "10fd017caa7bd0119e0c00a0c922e6ec10fd017caa7bd0119e0c00a0c922e6ec",
  "hex"
);
var ITSFHeaderParser = class {
  static parse(reader) {
    const start = reader.position;
    const prefix = readBytes(reader, 12, "ITSF header");
    const signature = prefix.toString("ascii", 0, 4);
    if (signature !== "ITSF") throw new Error(`\u65E0\u6548\u7684 ITSF \u7B7E\u540D: ${signature}`);
    const version = prefix.readUInt32LE(4);
    if (version !== 2 && version !== 3)
      throw new Error(`\u4E0D\u652F\u6301\u7684 ITSF \u7248\u672C: ${version}`);
    const headerLength = prefix.readUInt32LE(8);
    if (headerLength < (version === 2 ? 88 : 96)) {
      throw new Error(`ITSF \u5934\u90E8\u957F\u5EA6\u65E0\u6548: ${headerLength}`);
    }
    reader.setPosition(start, 0);
    const data = readBytes(reader, headerLength, "ITSF header");
    const guids = data.subarray(24, 56);
    if (!guids.equals(GUIDS) && !(version === 3 && guids.equals(FPC_V3_GUIDS)))
      throw new Error("\u65E0\u6548\u7684 ITSF GUID");
    const result = {
      signature,
      version,
      headerLength,
      unknown1: data.readUInt32LE(12),
      timestamp: data.readUInt32BE(16),
      languageId: data.readUInt32LE(20),
      // These describe auxiliary header section 0, not the content data section.
      unknown2: readUInt64LE(data, 56, "ITSF header section 0 offset"),
      unknown3: readUInt64LE(data, 64, "ITSF header section 0 length"),
      directoryOffset: readUInt64LE(data, 72, "ITSF directory offset"),
      directoryLength: readUInt64LE(data, 80, "ITSF directory length"),
      unknown4: version === 3 ? readUInt64LE(data, 88, "ITSF data offset") : 0
    };
    if (!this.validate(result))
      throw new Error("ITSF \u5934\u90E8\u9A8C\u8BC1\u5931\u8D25: invalid range");
    return result;
  }
  static validate(header) {
    if (header.signature !== "ITSF" || header.version !== 2 && header.version !== 3)
      return false;
    if (!isUInt(header.headerLength) || header.headerLength < (header.version === 2 ? 88 : 96))
      return false;
    if (!isUInt(header.directoryOffset) || header.directoryOffset < header.headerLength || !isUInt(header.directoryLength) || header.directoryLength < 84)
      return false;
    if (![header.unknown2, header.unknown3, header.unknown4].every(isUInt))
      return false;
    try {
      checkedEnd(
        header.directoryOffset,
        header.directoryLength,
        "ITSF directory"
      );
      checkedEnd(header.unknown2, header.unknown3, "ITSF header section 0");
    } catch {
      return false;
    }
    return true;
  }
  static getSummary(header) {
    return [
      `ITSF \u7248\u672C: ${header.version}`,
      `\u5934\u90E8\u957F\u5EA6: ${header.headerLength} \u5B57\u8282`,
      `\u8BED\u8A00 ID: ${header.languageId}`,
      `\u76EE\u5F55\u504F\u79FB: 0x${header.directoryOffset.toString(16)}`,
      `\u76EE\u5F55\u957F\u5EA6: ${header.directoryLength} \u5B57\u8282`
    ].join("\n");
  }
};

// src/core/headers/itsp-header.ts
init_browser_buffer();
var GUID = import_buffer.Buffer.from("6a92025d2e21d0119df900a0c922e6ec", "hex");
var ITSPHeaderParser = class {
  static parse(reader) {
    const start = reader.position;
    const prefix = readBytes(reader, 12, "ITSP header");
    const signature = prefix.toString("ascii", 0, 4);
    if (signature !== "ITSP") throw new Error(`\u65E0\u6548\u7684 ITSP \u7B7E\u540D: ${signature}`);
    const version = prefix.readUInt32LE(4);
    if (version !== 1) throw new Error(`\u4E0D\u652F\u6301\u7684 ITSP \u7248\u672C: ${version}`);
    const headerLength = prefix.readUInt32LE(8);
    if (headerLength < 84)
      throw new Error(`ITSP \u5934\u90E8\u957F\u5EA6\u65E0\u6548: ${headerLength}`);
    reader.setPosition(start, 0);
    const data = readBytes(reader, headerLength, "ITSP header");
    if (!data.subarray(52, 68).equals(GUID))
      throw new Error("\u65E0\u6548\u7684 ITSP GUID");
    const header = {
      signature,
      version,
      headerLength,
      unknown1: data.readUInt32LE(12),
      chunkSize: data.readUInt32LE(16),
      density: data.readUInt32LE(20),
      depth: data.readUInt32LE(24),
      rootIndex: data.readInt32LE(28),
      // Retain the public field names: these are actually first/last PMGL.
      firstPMGI: data.readUInt32LE(32),
      lastPMGI: data.readUInt32LE(36),
      unknown2: data.readUInt32LE(40)
    };
    const numChunks = data.readUInt32LE(44);
    if (!this.validate(header) || numChunks === 0 || header.lastPMGI >= numChunks || header.rootIndex >= numChunks || header.depth > numChunks) {
      throw new Error("ITSP \u5934\u90E8\u9A8C\u8BC1\u5931\u8D25: invalid chunk range");
    }
    return header;
  }
  static validate(header) {
    return header.signature === "ITSP" && header.version === 1 && isUInt(header.headerLength) && header.headerLength >= 84 && isUInt(header.chunkSize) && header.chunkSize >= 22 && isUInt(header.density) && header.density <= 31 && isUInt(header.depth) && header.depth >= 1 && Number.isInteger(header.rootIndex) && header.rootIndex >= -1 && header.rootIndex <= 4294967295 && isUInt(header.firstPMGI) && isUInt(header.lastPMGI) && header.firstPMGI <= header.lastPMGI;
  }
  static getSummary(header) {
    return [
      `ITSP \u7248\u672C: ${header.version}`,
      `\u5934\u90E8\u957F\u5EA6: ${header.headerLength} \u5B57\u8282`,
      `\u5757\u5927\u5C0F: ${header.chunkSize} \u5B57\u8282`,
      `\u5BC6\u5EA6: ${header.density}`,
      `\u6DF1\u5EA6: ${header.depth}`,
      `\u6839\u7D22\u5F15: ${header.rootIndex}`,
      `\u9996\u4E2A PMGL: ${header.firstPMGI}`,
      `\u6700\u540E PMGL: ${header.lastPMGI}`
    ].join("\n");
  }
};

// src/core/headers/lzxc-header.ts
init_browser_buffer();
var LZXCHeaderParser = class {
  static parse(reader) {
    const start = reader.position;
    const prefix = readBytes(reader, 12, "LZXC ControlData");
    const words = prefix.readUInt32LE(0);
    const signature = prefix.toString("ascii", 4, 8);
    if (signature !== "LZXC") throw new Error(`\u65E0\u6548\u7684 LZXC \u7B7E\u540D: ${signature}`);
    const version = prefix.readUInt32LE(8);
    if (version !== 1 && version !== 2)
      throw new Error(`\u4E0D\u652F\u6301\u7684 LZXC \u7248\u672C: ${version}`);
    if (words < (version === 1 ? 5 : 6))
      throw new Error("LZXC ControlData \u957F\u5EA6\u524D\u7F00\u65E0\u6548");
    reader.setPosition(start, 0);
    const data = readBytes(reader, 4 + words * 4, "LZXC ControlData");
    const unit = version === 2 ? 32768 : 1;
    const header = {
      signature,
      version,
      resetInterval: data.readUInt32LE(12) * unit,
      windowSize: data.readUInt32LE(16) * unit,
      // This on-disk field is windowsPerReset, not a byte count.
      cacheSize: data.readUInt32LE(20),
      unknown: words >= 6 ? data.readUInt32LE(24) : 0
    };
    if (!this.validate(header)) throw new Error("LZXC \u5934\u90E8\u9A8C\u8BC1\u5931\u8D25");
    return header;
  }
  static validate(header) {
    return header.signature === "LZXC" && (header.version === 1 || header.version === 2) && this.WINDOW_SIZES.includes(header.windowSize) && isUInt(header.resetInterval) && header.resetInterval > 0 && header.resetInterval % 32768 === 0 && isUInt(header.cacheSize) && isUInt(header.unknown);
  }
  static getWindowSizeString(windowSize) {
    if (windowSize >= 1024 * 1024) return `${windowSize / (1024 * 1024)}MB`;
    if (windowSize >= 1024) return `${windowSize / 1024}KB`;
    return `${windowSize}B`;
  }
  static getSummary(header) {
    return [
      `LZXC \u7248\u672C: ${header.version}`,
      `\u91CD\u7F6E\u95F4\u9694: ${header.resetInterval}`,
      `\u7A97\u53E3\u5927\u5C0F: ${this.getWindowSizeString(header.windowSize)}`,
      `\u6BCF\u6B21\u91CD\u7F6E\u7684\u7A97\u53E3\u6570: ${header.cacheSize}`
    ].join("\n");
  }
  static getSupportedWindowSizes() {
    return [...this.WINDOW_SIZES];
  }
};
LZXCHeaderParser.WINDOW_SIZES = [
  32768,
  65536,
  131072,
  262144,
  524288,
  1048576,
  2097152
];

// src/core/files/byte-source.ts
init_browser_buffer();
function requireSourceRange(source, offset, length, label) {
  if (!Number.isSafeInteger(source.size) || source.size < 0 || checkedEnd(offset, length, label) > source.size)
    throw new Error(`${label}: truncated or out of bounds`);
}
var MemoryByteSource = class {
  constructor(buffer) {
    this.buffer = buffer;
  }
  get size() {
    return this.buffer.length;
  }
  read(offset, length) {
    requireSourceRange(this, offset, length, "CHM source");
    return this.buffer.subarray(offset, offset + length);
  }
};
function asByteSource(input) {
  return "read" in input && "size" in input ? input : new MemoryByteSource(input.buffer);
}

// src/core/directory/directory-parser.ts
init_browser_buffer();
var DirectoryParser = class {
  static parse(reader, itspHeader, numChunks) {
    if (!ITSPHeaderParser.validate(itspHeader) || !isUInt(numChunks) || numChunks === 0 || itspHeader.lastPMGI >= numChunks) {
      throw new Error("\u65E0\u6548\u7684\u76EE\u5F55\u5757\u8303\u56F4");
    }
    const size = itspHeader.chunkSize;
    requireRange(
      reader.buffer,
      reader.position,
      numChunks * size,
      "Directory chunks"
    );
    const entries = /* @__PURE__ */ new Map();
    const names = /* @__PURE__ */ new Set();
    const blocks = [];
    for (let index = 0; index < numChunks; index++) {
      const data = readBytes(reader, size, `Directory chunk ${index}`);
      const signature = data.toString("ascii", 0, 4);
      if (signature !== "PMGL" && signature !== "PMGI")
        throw new Error(`\u672A\u77E5\u7684\u5757\u7B7E\u540D: ${signature}`);
      const leaf = signature === "PMGL";
      const headerSize = leaf ? 20 : 8;
      const freeSpace = data.readUInt32LE(4);
      if (freeSpace < 2 || freeSpace > size - headerSize)
        throw new Error(`${signature}: invalid free space`);
      const end = size - freeSpace;
      const count = data.readUInt16LE(size - 2);
      const groupSize = 1 + 2 ** itspHeader.density;
      const quickRefs = Math.max(0, Math.ceil(count / groupSize) - 1);
      if (2 + quickRefs * 2 > freeSpace)
        throw new Error(`${signature}: truncated quickref table`);
      const block = {
        leaf,
        previous: leaf ? data.readInt32LE(12) : -1,
        next: leaf ? data.readInt32LE(16) : -1,
        children: [],
        fpcQuickRefs: false
      };
      const indexNames = /* @__PURE__ */ new Set();
      let standardQuickRefs = true;
      let fpcQuickRefs = itspHeader.density === 2;
      let previousEntryOffset = headerSize;
      let offset = headerSize;
      for (let i = 0; i < count; i++) {
        if (i > 0 && i % groupSize === 0) {
          const quickRef = data.readUInt16LE(size - 2 - i / groupSize * 2);
          standardQuickRefs && (standardQuickRefs = quickRef === offset - headerSize);
          fpcQuickRefs && (fpcQuickRefs = quickRef === previousEntryOffset - headerSize);
          if (!standardQuickRefs && !fpcQuickRefs)
            throw new Error(`${signature}: invalid quickref offset`);
        }
        previousEntryOffset = offset;
        const nameLength = this.readEncInt(data, offset, end);
        offset = nameLength.nextOffset;
        if (nameLength.value === 0 || nameLength.value > end - offset)
          throw new Error(`${signature}: invalid name length`);
        const rawName = data.subarray(offset, offset + nameLength.value);
        const name = rawName.toString("utf8");
        if (name.includes("\0") || !import_buffer.Buffer.from(name, "utf8").equals(rawName))
          throw new Error(`${signature}: invalid UTF-8 name`);
        offset += nameLength.value;
        const key = name.toLowerCase();
        if (!leaf) {
          if (indexNames.has(key)) throw new Error(`\u91CD\u590D\u7684 PMGI \u6761\u76EE: ${name}`);
          indexNames.add(key);
          const child = this.readEncInt(data, offset, end);
          offset = child.nextOffset;
          if (child.value >= numChunks || child.value === index || block.children.includes(child.value))
            throw new Error("PMGI: invalid child chunk");
          block.children.push(child.value);
        } else {
          if (names.has(key)) throw new Error(`\u91CD\u590D\u7684\u76EE\u5F55\u6761\u76EE: ${name}`);
          names.add(key);
          const section = this.readEncInt(data, offset, end);
          const entryOffset = this.readEncInt(data, section.nextOffset, end);
          const length = this.readEncInt(data, entryOffset.nextOffset, end);
          offset = length.nextOffset;
          if (section.value > 1)
            throw new Error(`\u65E0\u6548\u7684\u8282\u7F16\u53F7: ${section.value}`);
          checkedEnd(
            entryOffset.value,
            length.value,
            `Directory entry ${name}`
          );
          const compressed = section.value === 1;
          entries.set(name, {
            name,
            isCompressed: compressed,
            offset: entryOffset.value,
            length: length.value,
            ...compressed ? { uncompressedLength: length.value } : {},
            section: section.value
          });
        }
      }
      if (offset !== end)
        throw new Error(`${signature}: entry count/data length mismatch`);
      if (!leaf && count === 0) throw new Error("PMGI: empty index chunk");
      block.fpcQuickRefs = quickRefs > 0 && fpcQuickRefs && !standardQuickRefs;
      if (block.fpcQuickRefs && count % groupSize === 0) {
        const fpcRefs = count / groupSize;
        if (2 + fpcRefs * 2 > freeSpace)
          throw new Error(`${signature}: truncated quickref table`);
        if (data.readUInt16LE(size - 2 - fpcRefs * 2) !== previousEntryOffset - headerSize)
          throw new Error(`${signature}: invalid quickref offset`);
      }
      blocks.push(block);
    }
    this.validateBlocks(blocks, itspHeader);
    return { entries, rootPath: "/" };
  }
  static readEncInt(data, offset, end) {
    let value = 0;
    for (let i = 0; i < 8; i++) {
      if (offset >= end)
        throw new Error("ENCINT: truncated at entry data boundary");
      const byte = data[offset++];
      const digit = byte & 127;
      if (i === 0 && byte === 128)
        throw new Error("ENCINT: non-canonical leading zero");
      if (value > Math.floor((Number.MAX_SAFE_INTEGER - digit) / 128))
        throw new Error("ENCINT: exceeds safe integer range");
      value = value * 128 + digit;
      if ((byte & 128) === 0) return { value, nextOffset: offset };
    }
    throw new Error("ENCINT: too many bytes");
  }
  static validateBlocks(blocks, header) {
    const seen = /* @__PURE__ */ new Set();
    let index = header.firstPMGI;
    if (index === 1 && blocks[0]?.leaf && blocks[0].fpcQuickRefs && blocks[0].previous === -1 && blocks[0].next === 1 && blocks[1]?.previous === 0)
      index = 0;
    let previous = -1;
    while (index !== -1) {
      const block = blocks[index];
      if (!block?.leaf || seen.has(index) || block.previous !== previous)
        throw new Error("PMGL: invalid linked chunk chain");
      seen.add(index);
      previous = index;
      index = block.next;
    }
    if (previous !== header.lastPMGI || seen.size !== blocks.filter((block) => block.leaf).length)
      throw new Error("PMGL: missing or unlinked leaf chunk");
    const root = header.rootIndex === 4294967295 ? -1 : header.rootIndex;
    if (root === -1) {
      if (header.depth !== 1 || blocks.some((block) => !block.leaf))
        throw new Error("PMGI: missing root index");
      return;
    }
    if (!blocks[root]) throw new Error("PMGI: root index out of bounds");
    if (blocks[root].leaf) {
      if (header.depth !== 1 || blocks.some((block) => !block.leaf))
        throw new Error("PMGI: invalid root depth");
      return;
    }
    const visited = /* @__PURE__ */ new Set();
    const pending = [{ index: root, depth: 1 }];
    while (pending.length > 0) {
      const current = pending.pop();
      if (visited.has(current.index))
        throw new Error("PMGI: cycle or duplicate child");
      visited.add(current.index);
      const block = blocks[current.index];
      if (block.leaf) {
        if (current.depth !== header.depth)
          throw new Error("PMGI: leaf depth mismatch");
      } else {
        if (current.depth >= header.depth)
          throw new Error("PMGI: index depth mismatch");
        for (const child of block.children)
          pending.push({ index: child, depth: current.depth + 1 });
      }
    }
    if (visited.size !== blocks.length)
      throw new Error("PMGI: unreachable directory chunk");
  }
  static validate(directory) {
    if (!(directory.entries instanceof Map)) return false;
    const names = /* @__PURE__ */ new Set();
    for (const [name, entry] of directory.entries) {
      const key = name.toLowerCase();
      if (!name || name.includes("\0") || name !== entry.name || names.has(key) || entry.section !== 0 && entry.section !== 1 || entry.isCompressed !== (entry.section === 1))
        return false;
      names.add(key);
      try {
        checkedEnd(entry.offset, entry.length, name);
      } catch {
        return false;
      }
      if (entry.uncompressedLength !== void 0 && entry.uncompressedLength !== entry.length)
        return false;
    }
    return true;
  }
  static getSummary(directory) {
    const totalFiles = directory.entries.size;
    const compressedFiles = Array.from(directory.entries.values()).filter(
      (entry) => entry.isCompressed
    ).length;
    const totalSize = Array.from(directory.entries.values()).reduce(
      (sum, entry) => sum + entry.length,
      0
    );
    return [
      `\u603B\u6587\u4EF6\u6570: ${totalFiles}`,
      `\u538B\u7F29\u6587\u4EF6\u6570: ${compressedFiles}`,
      `\u672A\u538B\u7F29\u6587\u4EF6\u6570: ${totalFiles - compressedFiles}`,
      `\u603B\u5927\u5C0F: ${this.formatBytes(totalSize)}`
    ].join("\n");
  }
  static formatBytes(bytes) {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${bytes} \u5B57\u8282`;
  }
};

// src/core/lzx/reset-table.ts
init_browser_buffer();
var ResetTableProcessor = class {
  constructor() {
    this.resetTable = null;
  }
  parseResetTable(reader) {
    this.reset();
    const start = reader.position;
    const data = readBytes(reader, 40, "ResetTable header");
    const version = data.readUInt32LE(0);
    const entryCount = data.readUInt32LE(4);
    const entrySize = data.readUInt32LE(8);
    const tableOffset = data.readUInt32LE(12);
    if (version !== 2) throw new Error(`\u4E0D\u652F\u6301\u7684\u91CD\u7F6E\u8868\u7248\u672C: ${version}`);
    if (entrySize !== 8) throw new Error(`\u65E0\u6548\u7684\u6761\u76EE\u5927\u5C0F: ${entrySize}`);
    if (tableOffset < 40) throw new Error(`\u65E0\u6548\u7684\u8868\u504F\u79FB: ${tableOffset}`);
    const uncompressedLength = readUInt64LE(
      data,
      16,
      "ResetTable uncompressed length"
    );
    const compressedLength = readUInt64LE(
      data,
      24,
      "ResetTable compressed length"
    );
    const blockSize = readUInt64LE(data, 32, "ResetTable block size");
    if (blockSize !== 32768) throw new Error(`\u65E0\u6548\u7684\u5757\u5927\u5C0F: ${blockSize}`);
    const blockCount = Math.ceil(uncompressedLength / blockSize);
    const hasTerminal = blockCount > 0 && entryCount === blockCount + 1;
    if (entryCount !== blockCount && !hasTerminal)
      throw new Error(
        "ResetTable: block count does not match uncompressed length"
      );
    requireRange(
      reader.buffer,
      start,
      tableOffset + entryCount * entrySize,
      "ResetTable entries"
    );
    reader.setPosition(start + tableOffset, 0);
    const offsets = readBytes(
      reader,
      entryCount * entrySize,
      "ResetTable entries"
    );
    if (hasTerminal && readUInt64LE(
      offsets,
      blockCount * entrySize,
      "ResetTable terminal compressed offset"
    ) !== compressedLength)
      throw new Error(
        "ResetTable: terminal offset does not match compressed length"
      );
    const entries = [];
    for (let i = 0; i < blockCount; i++) {
      entries.push({
        compressedLength: readUInt64LE(
          offsets,
          i * entrySize,
          "ResetTable compressed offset"
        ),
        uncompressedLength: Math.min(
          blockSize,
          uncompressedLength - i * blockSize
        )
      });
    }
    const table = {
      version,
      blockCount,
      entrySize,
      tableOffset,
      uncompressedLength,
      compressedLength,
      blockSize,
      entries
    };
    if (!this.isValid(table))
      throw new Error("ResetTable: invalid cumulative compressed offsets");
    this.resetTable = table;
    return table;
  }
  getBlockInfo(blockIndex) {
    const entry = Number.isInteger(blockIndex) ? this.resetTable?.entries[blockIndex] : void 0;
    return entry ? { ...entry } : null;
  }
  getBlockCount() {
    return this.resetTable?.blockCount ?? 0;
  }
  getBlockSize() {
    return this.resetTable?.blockSize ?? 0;
  }
  /** Offset relative to the compressed Content stream, never to ResetTable. */
  calculateBlockOffset(blockIndex) {
    if (!this.resetTable) throw new Error("\u91CD\u7F6E\u8868\u672A\u521D\u59CB\u5316");
    const entry = this.getBlockInfo(blockIndex);
    if (!entry) throw new Error(`\u65E0\u6548\u7684\u5757\u7D22\u5F15: ${blockIndex}`);
    return entry.compressedLength;
  }
  /** Find a frame by its compressed Content-stream offset (end exclusive). */
  findBlockByOffset(offset) {
    const table = this.resetTable;
    if (!table || !isUInt(offset) || offset >= table.compressedLength)
      return -1;
    let low = 0;
    let high = table.entries.length - 1;
    while (low <= high) {
      const middle = Math.floor((low + high) / 2);
      if (table.entries[middle].compressedLength <= offset) low = middle + 1;
      else high = middle - 1;
    }
    return high;
  }
  isValid(table) {
    if (table.version !== 2 || table.entrySize !== 8 || table.tableOffset < 40 || table.blockSize !== 32768 || ![
      table.blockCount,
      table.tableOffset,
      table.compressedLength,
      table.uncompressedLength
    ].every(isUInt) || table.blockCount !== table.entries.length || table.blockCount !== Math.ceil(table.uncompressedLength / table.blockSize))
      return false;
    if (table.blockCount === 0)
      return table.compressedLength === 0 && table.uncompressedLength === 0;
    if (table.entries[0].compressedLength !== 0) return false;
    let previous = -1;
    for (let i = 0; i < table.entries.length; i++) {
      const entry = table.entries[i];
      if (!isUInt(entry.compressedLength) || entry.compressedLength <= previous || entry.compressedLength >= table.compressedLength || entry.uncompressedLength !== Math.min(
        table.blockSize,
        table.uncompressedLength - i * table.blockSize
      ))
        return false;
      previous = entry.compressedLength;
    }
    return true;
  }
  validate() {
    return this.resetTable !== null && this.isValid(this.resetTable);
  }
  getStatistics() {
    if (!this.resetTable) return "\u91CD\u7F6E\u8868\u672A\u521D\u59CB\u5316";
    const table = this.resetTable;
    const ratio = table.uncompressedLength === 0 ? 0 : table.compressedLength / table.uncompressedLength * 100;
    return [
      `\u91CD\u7F6E\u8868\u7248\u672C: ${table.version}`,
      `\u603B\u5757\u6570: ${table.blockCount}`,
      `\u5757\u5927\u5C0F: ${this.formatBytes(table.blockSize)}`,
      `\u603B\u538B\u7F29\u5927\u5C0F: ${this.formatBytes(table.compressedLength)}`,
      `\u603B\u672A\u538B\u7F29\u5927\u5C0F: ${this.formatBytes(table.uncompressedLength)}`,
      `\u538B\u7F29\u7387: ${ratio.toFixed(2)}%`
    ].join("\n");
  }
  formatBytes(bytes) {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${bytes} \u5B57\u8282`;
  }
  reset() {
    this.resetTable = null;
  }
  getResetTable() {
    if (!this.resetTable) return null;
    return {
      ...this.resetTable,
      entries: this.resetTable.entries.map((entry) => ({ ...entry }))
    };
  }
};

// src/core/parser/chm-parser.ts
var STORAGE = "::DataSpace/Storage/MSCompressed/";
var CONTENT = `${STORAGE}Content`;
var CONTROL = `${STORAGE}ControlData`;
var RESET = `${STORAGE}Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable`;
var _CHMParser = class _CHMParser {
  constructor() {
    this.resetTableProcessor = new ResetTableProcessor();
  }
  parse(reader) {
    reader.setPosition(0, 0);
    const parsed = this.parseSource(new MemoryByteSource(reader.buffer));
    reader.setPosition(
      checkedEnd(
        parsed.header.itsf.directoryOffset,
        parsed.header.itsf.directoryLength,
        "ITSF directory"
      ),
      0
    );
    return parsed;
  }
  /** Reads only structural metadata; validates payload ranges without loading them. */
  parseSource(source) {
    this.reset();
    const parsed = this.parseStructure(source);
    const resetEntry = this.findEntry(parsed.directory, RESET);
    let resetTable = {
      version: 2,
      blockCount: 0,
      entrySize: 8,
      tableOffset: 40,
      uncompressedLength: 0,
      compressedLength: 0,
      blockSize: 32768,
      entries: []
    };
    if (resetEntry) {
      const base = this.dataOffset(parsed);
      resetTable = this.resetTableProcessor.parseResetTable(
        this.entryReader(source, base, resetEntry)
      );
      const content = this.findEntry(parsed.directory, CONTENT);
      if (resetTable.compressedLength !== content.length)
        throw new Error("ResetTable: compressed length does not match Content");
      for (const entry of parsed.directory.entries.values()) {
        if (entry.section === 1 && checkedEnd(entry.offset, entry.length, entry.name) > resetTable.uncompressedLength) {
          throw new Error(
            `Compressed entry outside uncompressed stream: ${entry.name}`
          );
        }
      }
    }
    return { ...parsed, resetTable };
  }
  parseStructure(source) {
    const prefix = this.readMetadata(
      source,
      0,
      Math.min(12, source.size),
      _CHMParser.MAX_HEADER_BYTES,
      "ITSF header"
    );
    if (prefix.length < 12)
      throw new Error("ITSF header: truncated or out of bounds");
    const version = prefix.readUInt32LE(4);
    if (prefix.toString("ascii", 0, 4) !== "ITSF" || version !== 2 && version !== 3)
      throw new Error("Invalid ITSF signature or version");
    const headerLength = prefix.readUInt32LE(8);
    const itsf = ITSFHeaderParser.parse(
      new BitReader(
        this.readMetadata(
          source,
          0,
          headerLength,
          _CHMParser.MAX_HEADER_BYTES,
          "ITSF header"
        )
      )
    );
    requireSourceRange(
      source,
      itsf.unknown2,
      itsf.unknown3,
      "ITSF auxiliary header section 0"
    );
    requireSourceRange(
      source,
      itsf.directoryOffset,
      itsf.directoryLength,
      "ITSF directory"
    );
    const directoryEnd = checkedEnd(
      itsf.directoryOffset,
      itsf.directoryLength,
      "ITSF directory"
    );
    const base = itsf.version === 3 ? itsf.unknown4 : directoryEnd;
    requireSourceRange(source, base, 0, "ITSF data section");
    const directoryReader = new BitReader(
      this.readMetadata(
        source,
        itsf.directoryOffset,
        itsf.directoryLength,
        _CHMParser.MAX_DIRECTORY_BYTES,
        "ITSF directory"
      )
    );
    const itsp = ITSPHeaderParser.parse(directoryReader);
    const chunkBytes = itsf.directoryLength - itsp.headerLength;
    const numChunks = directoryReader.buffer.readUInt32LE(44);
    if (chunkBytes !== numChunks * itsp.chunkSize)
      throw new Error("ITSP chunk count does not match directory length");
    const directory = DirectoryParser.parse(directoryReader, itsp, numChunks);
    if (!DirectoryParser.validate(directory))
      throw new Error("\u76EE\u5F55\u7ED3\u6784\u9A8C\u8BC1\u5931\u8D25");
    for (const entry of directory.entries.values()) {
      if (entry.section === 0) {
        requireSourceRange(
          source,
          checkedEnd(base, entry.offset, entry.name),
          entry.length,
          entry.name
        );
      }
    }
    const control = this.findEntry(directory, CONTROL);
    const content = this.findEntry(directory, CONTENT);
    const reset = this.findEntry(directory, RESET);
    const hasCompression = Boolean(control || content || reset) || Array.from(directory.entries.values()).some((entry) => entry.section === 1);
    let lzxc = {
      signature: "",
      version: 0,
      resetInterval: 0,
      windowSize: 0,
      cacheSize: 0,
      unknown: 0
    };
    if (hasCompression) {
      if (!control || !content || !reset)
        throw new Error(
          "\u7F3A\u5C11\u538B\u7F29\u5143\u6570\u636E: Content, ControlData and ResetTable are required"
        );
      for (const entry of [control, content, reset]) {
        if (entry.section !== 0)
          throw new Error(
            `Compression metadata must be in section 0: ${entry.name}`
          );
      }
      lzxc = LZXCHeaderParser.parse(this.entryReader(source, base, control));
    }
    const contentOffset = content ? checkedEnd(base, content.offset, CONTENT) : base;
    return { header: { itsf, itsp, lzxc }, directory, contentOffset };
  }
  dataOffset(parsed) {
    const itsf = parsed.header.itsf;
    return itsf.version === 3 ? itsf.unknown4 : checkedEnd(
      itsf.directoryOffset,
      itsf.directoryLength,
      "ITSF directory"
    );
  }
  findEntry(directory, name) {
    const lower = name.toLowerCase();
    for (const entry of directory.entries.values())
      if (entry.name.toLowerCase() === lower) return entry;
    return void 0;
  }
  entryReader(source, base, entry) {
    if (entry.section !== 0)
      throw new Error(
        `Compression metadata must be in section 0: ${entry.name}`
      );
    const start = checkedEnd(base, entry.offset, entry.name);
    return new BitReader(
      this.readMetadata(
        source,
        start,
        entry.length,
        _CHMParser.MAX_METADATA_STREAM_BYTES,
        entry.name
      )
    );
  }
  readMetadata(source, offset, length, maxBytes, label) {
    requireSourceRange(source, offset, length, label);
    if (length > maxBytes)
      throw new RangeError(
        `${label}: metadata budget exceeded (${length} bytes > ${maxBytes} bytes)`
      );
    return source.read(offset, length);
  }
  /** Omit ResetTable from the result, but never hide corrupt compression metadata. */
  quickParse(reader) {
    const { header, directory, contentOffset } = this.parse(reader);
    return { header, directory, contentOffset };
  }
  reset() {
    this.resetTableProcessor.reset();
  }
};
/** Fixed per-ITSF-header allocation budget, for memory and random-access input. */
_CHMParser.MAX_HEADER_BYTES = 1024 * 1024;
/** Fixed allocation budget for the complete ITSP/PMGL/PMGI directory. */
_CHMParser.MAX_DIRECTORY_BYTES = 64 * 1024 * 1024;
/** Per-stream allocation budget for ControlData and ResetTable, not Content. */
_CHMParser.MAX_METADATA_STREAM_BYTES = 16 * 1024 * 1024;
var CHMParser = _CHMParser;

// src/core/files/file-reconstructor.ts
init_browser_buffer();

// src/core/lzx/lzx-decoder.ts
init_browser_buffer();

// src/core/lzx/sliding-window.ts
init_browser_buffer();
var SlidingWindow = class {
  constructor(windowSize) {
    this.size = windowSize;
    this.data = import_buffer.Buffer.alloc(windowSize);
    this.position = 0;
  }
  /**
   * 写入数据到窗口
   * @param data 要写入的数据
   */
  write(data) {
    for (let i = 0; i < data.length; i++) {
      this.data[this.position] = data[i];
      this.position = (this.position + 1) % this.size;
    }
  }
  /**
   * 写入单个字节到窗口
   * @param byte 要写入的字节
   */
  writeByte(byte) {
    this.data[this.position] = byte;
    this.position = (this.position + 1) % this.size;
  }
  /**
   * 从指定偏移位置读取数据
   * @param offset 回退偏移量
   * @param length 要读取的长度
   * @returns 读取的数据
   */
  readBack(offset, length) {
    if (offset <= 0 || offset > this.size) {
      throw new Error(`\u65E0\u6548\u7684\u504F\u79FB\u91CF: ${offset}`);
    }
    if (length <= 0) {
      throw new Error(`\u65E0\u6548\u7684\u957F\u5EA6: ${length}`);
    }
    const result = import_buffer.Buffer.alloc(length);
    let readPosition = (this.position - offset + this.size) % this.size;
    for (let i = 0; i < length; i++) {
      result[i] = this.data[readPosition];
      readPosition = (readPosition + 1) % this.size;
    }
    return result;
  }
  /**
   * 从指定偏移位置读取单个字节
   * @param offset 回退偏移量
   * @returns 读取的字节
   */
  readBackByte(offset) {
    if (offset <= 0 || offset > this.size) {
      throw new Error(`\u65E0\u6548\u7684\u504F\u79FB\u91CF: ${offset}`);
    }
    const readPosition = (this.position - offset + this.size) % this.size;
    return this.data[readPosition];
  }
  /**
   * 复制数据（用于 LZ77 匹配）
   * @param offset 回退偏移量
   * @param length 复制长度
   * @returns 复制的数据
   */
  copyData(offset, length) {
    const result = import_buffer.Buffer.alloc(length);
    for (let i = 0; i < length; i++) {
      const byte = this.readBackByte(offset);
      result[i] = byte;
      this.writeByte(byte);
    }
    return result;
  }
  /**
   * 重置窗口
   */
  reset() {
    this.data.fill(0);
    this.position = 0;
  }
  /**
   * 获取当前窗口使用量
   * @returns 使用的字节数
   */
  getUsage() {
    return Math.min(this.position, this.size);
  }
  /**
   * 获取窗口剩余空间
   * @returns 剩余字节数
   */
  getRemainingSpace() {
    return this.size - this.getUsage();
  }
  /**
   * 检查是否可以进行指定长度的回退读取
   * @param offset 回退偏移量
   * @param length 读取长度
   * @returns 是否可以读取
   */
  canReadBack(offset, length) {
    if (offset <= 0 || offset > this.size) {
      return false;
    }
    if (length <= 0) {
      return false;
    }
    const availableData = this.getUsage();
    return offset <= availableData;
  }
  /**
   * 获取窗口状态信息
   * @returns 窗口状态字符串
   */
  getStatus() {
    return [
      `\u7A97\u53E3\u5927\u5C0F: ${this.size} \u5B57\u8282`,
      `\u5F53\u524D\u4F4D\u7F6E: ${this.position}`,
      `\u4F7F\u7528\u91CF: ${this.getUsage()} \u5B57\u8282`,
      `\u5229\u7528\u7387: ${(this.getUsage() / this.size * 100).toFixed(2)}%`
    ].join("\n");
  }
  /**
   * 创建窗口的快照（用于调试）
   * @param start 开始位置
   * @param length 快照长度
   * @returns 快照数据
   */
  snapshot(start = 0, length = Math.min(32, this.size)) {
    const snapshotLength = Math.min(length, this.size - start);
    return this.data.subarray(start, start + snapshotLength);
  }
};

// src/core/lzx/lzx-bit-reader.ts
init_browser_buffer();
var LZXBitReader = class {
  constructor(input) {
    this.input = input;
    this.position = 0;
    this.word = 0;
    this.bitsLeft = 0;
  }
  read(bits) {
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) {
      throw new Error("Invalid LZX bit count");
    }
    if (bits > this.bitsLeft + Math.floor(this.remainingBytes / 2) * 16) {
      throw new Error("Truncated LZX input");
    }
    let value = 0;
    while (bits > 0) {
      if (this.bitsLeft === 0) {
        this.requireBytes(2);
        this.word = this.input[this.position] | this.input[this.position + 1] << 8;
        this.position += 2;
        this.bitsLeft = 16;
      }
      const take = Math.min(bits, this.bitsLeft);
      this.bitsLeft -= take;
      value = value * 2 ** take + (this.word >>> this.bitsLeft & 2 ** take - 1);
      bits -= take;
    }
    return value;
  }
  /** A raw block discards 1..16 bits, including a whole word if aligned. */
  alignUncompressed() {
    if (this.bitsLeft === 0) this.read(16);
    this.bitsLeft = 0;
  }
  /** Unlike raw block alignment, frame alignment discards only 0..15 bits. */
  alignFrame() {
    this.bitsLeft = 0;
  }
  readRaw(length) {
    if (this.bitsLeft !== 0) throw new Error("Unaligned LZX raw read");
    this.requireBytes(length);
    const bytes = this.input.subarray(this.position, this.position + length);
    this.position += length;
    return bytes;
  }
  readUInt32LE() {
    const bytes = this.readRaw(4);
    return (bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24) >>> 0;
  }
  get remainingBytes() {
    return this.input.length - this.position;
  }
  requireBytes(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.remainingBytes) {
      throw new Error("Truncated LZX input");
    }
  }
};

// src/core/lzx/lzx-decoder.ts
var CanonicalTree = class {
  constructor(lengths, allowEmpty = false) {
    this.counts = new Uint16Array(17);
    this.firstCodes = new Uint32Array(17);
    this.firstSymbols = new Uint16Array(17);
    this.symbols = [];
    this.maxLength = 0;
    for (const length of lengths) {
      if (!Number.isInteger(length) || length < 0 || length > 16) {
        throw new Error("Invalid LZX Huffman code length");
      }
      if (length !== 0) {
        this.counts[length]++;
        this.maxLength = Math.max(this.maxLength, length);
      }
    }
    if (this.maxLength === 0) {
      if (allowEmpty) return;
      throw new Error("Empty LZX Huffman tree");
    }
    let free = 1;
    let code = 0;
    for (let length = 1; length <= 16; length++) {
      free = free * 2 - this.counts[length];
      if (free < 0) throw new Error("Oversubscribed LZX Huffman tree");
      code = (code + (this.counts[length - 1] ?? 0)) * 2;
      this.firstCodes[length] = code;
      this.firstSymbols[length] = this.symbols.length;
      for (let symbol = 0; symbol < lengths.length; symbol++) {
        if (lengths[symbol] === length) this.symbols.push(symbol);
      }
    }
    if (free !== 0) throw new Error("Incomplete LZX Huffman tree");
  }
  decode(reader) {
    let code = 0;
    for (let length = 1; length <= this.maxLength; length++) {
      code = code * 2 + reader.read(1);
      const index = code - this.firstCodes[length];
      if (index >= 0 && index < this.counts[length]) {
        return this.symbols[this.firstSymbols[length] + index];
      }
    }
    throw new Error("Invalid or empty LZX Huffman code");
  }
};
var _LZXDecoder = class _LZXDecoder {
  constructor(lzxcHeader) {
    this.lengthLengths = new Array(249).fill(0);
    this.positionBases = [];
    this.extraBits = [];
    this.mainTree = null;
    this.lengthTree = null;
    this.alignedTree = null;
    this.recentOffsets = [1, 1, 1];
    this.headerRead = false;
    this.intelFileSize = 0;
    this.intelStarted = false;
    this.blockType = 0;
    this.blockRemaining = 0;
    this.oddRawPadding = false;
    this.historySize = 0;
    this.windowSize = lzxcHeader.windowSize;
    this.resetInterval = lzxcHeader.resetInterval;
    if (!this.validate())
      throw new Error("Invalid LZX window size or reset interval");
    this.window = new SlidingWindow(this.windowSize);
    const slots = [30, 32, 34, 36, 38, 42, 50][Math.log2(this.windowSize) - 15];
    this.mainLengths = new Array(256 + slots * 8).fill(0);
    let base = 0;
    for (let slot = 0; slot < slots; slot++) {
      const extra = slot < 4 ? 0 : Math.min(17, Math.floor(slot / 2) - 1);
      this.positionBases.push(base);
      this.extraBits.push(extra);
      base += 2 ** extra;
    }
  }
  /**
   * Compatibility entry point for a contiguous LZX stream. The existing byte
   * reader must be byte-aligned; its bytes are read in LZX word order here.
   * Each call starts a new stream. Success advances the supplied reader;
   * failure leaves its cursor unchanged and clears the decoder. A partial
   * match at the requested endpoint is allowed, but never across a 32 KiB
   * boundary. For Intel-filtered prefixes use decodeFrames with lastFrameSize.
   */
  decode(reader, size) {
    this.reset();
    this.checkOutputSize(size);
    if (reader.bitPosition !== 0 || !Number.isSafeInteger(reader.position) || reader.position < 0 || reader.position > reader.buffer.length) {
      throw new Error("LZX input reader must be byte-aligned and in bounds");
    }
    const input = new LZXBitReader(reader.buffer.subarray(reader.position));
    const chunks = [];
    try {
      for (let position = 0, frame = 0; position < size; frame++) {
        this.beginFrame(frame);
        const length = Math.min(_LZXDecoder.FRAME_SIZE, size - position);
        chunks.push(this.readFrame(input, length, frame));
        position += length;
      }
      const output = import_buffer.Buffer.concat(chunks, size);
      reader.position += input.position;
      return output;
    } catch (error) {
      this.reset();
      throw error;
    }
  }
  /**
   * Decode frame buffers from the nearest reset point. startFrame is the
   * absolute 32 KiB frame index, not an index into frames, and must be reset
   * aligned. outputSize is the requested output prefix. For a prefix ending
   * inside a physical frame, supply that frame's actual unpacked length as
   * lastFrameSize (32768 for CHM, including CHM's final padded frame). That
   * whole frame is decoded and Intel-filtered before returning the prefix.
   * Without lastFrameSize, the requested end is treated as the physical end
   * for Intel tail exclusion, retaining support for short CAB frames.
   * State persists within this call, never between calls; errors clear it.
   */
  decodeFrames(frames, outputSize, startFrame = 0, lastFrameSize) {
    this.reset();
    this.checkOutputSize(outputSize);
    const resetFrames = this.resetInterval / _LZXDecoder.FRAME_SIZE;
    if (!Number.isSafeInteger(startFrame) || startFrame < 0 || startFrame > Math.floor(Number.MAX_SAFE_INTEGER / _LZXDecoder.FRAME_SIZE) - frames.length || startFrame % resetFrames !== 0) {
      throw new Error(
        "LZX startFrame must be an absolute reset-aligned frame index"
      );
    }
    if (frames.length !== Math.ceil(outputSize / _LZXDecoder.FRAME_SIZE)) {
      throw new Error("LZX frame count does not match output size");
    }
    const lastRequested = outputSize === 0 ? 0 : outputSize - (frames.length - 1) * _LZXDecoder.FRAME_SIZE;
    const lastPhysical = lastFrameSize ?? lastRequested;
    if (!Number.isInteger(lastPhysical) || lastPhysical < lastRequested || lastPhysical > _LZXDecoder.FRAME_SIZE || outputSize === 0 && lastPhysical !== 0) {
      throw new Error("Invalid LZX lastFrameSize");
    }
    const chunks = [];
    let remaining = outputSize;
    try {
      for (let i = 0; i < frames.length; i++) {
        const frame = startFrame + i;
        this.beginFrame(frame);
        const input = new LZXBitReader(frames[i]);
        const length = Math.min(_LZXDecoder.FRAME_SIZE, remaining);
        const physical = i === frames.length - 1 ? lastPhysical : _LZXDecoder.FRAME_SIZE;
        const decoded = this.readFrame(
          input,
          physical,
          frame,
          lastFrameSize === void 0
        );
        chunks.push(decoded.subarray(0, length));
        remaining -= length;
      }
      return import_buffer.Buffer.concat(chunks, outputSize);
    } catch (error) {
      this.reset();
      throw error;
    }
  }
  /**
   * Lazily decode a reset-aligned sequence, retaining only the dictionary and
   * current physical frame. Unlike decodeFrames, outputSize is not an aggregate
   * allocation limit. The source must contain exactly ceil(outputSize / 32768)
   * frames; its count and any later errors are checked as iteration advances.
   * Prefix/physical-tail semantics match decodeFrames. Do not interleave other
   * operations on this decoder while iterating. Exhaustion, return() and errors
   * close the source and clear stream state; merely abandoning an iterator does
   * not run its cleanup.
   */
  *iterateFrames(frames, outputSize, startFrame = 0, lastFrameSize) {
    this.reset();
    if (!Number.isSafeInteger(outputSize) || outputSize < 0)
      throw new Error("Invalid LZX output size");
    const count = Math.ceil(outputSize / _LZXDecoder.FRAME_SIZE);
    const resetFrames = this.resetInterval / _LZXDecoder.FRAME_SIZE;
    if (!Number.isSafeInteger(startFrame) || startFrame < 0 || startFrame > Math.floor(Number.MAX_SAFE_INTEGER / _LZXDecoder.FRAME_SIZE) - count || startFrame % resetFrames !== 0)
      throw new Error(
        "LZX startFrame must be an absolute reset-aligned frame index"
      );
    const lastRequested = count === 0 ? 0 : outputSize - (count - 1) * _LZXDecoder.FRAME_SIZE;
    const lastPhysical = lastFrameSize ?? lastRequested;
    if (!Number.isInteger(lastPhysical) || lastPhysical < lastRequested || lastPhysical > _LZXDecoder.FRAME_SIZE || count === 0 && lastPhysical !== 0)
      throw new Error("Invalid LZX lastFrameSize");
    let index = 0;
    try {
      for (const bytes of frames) {
        if (index >= count)
          throw new Error("LZX frame count does not match output size");
        const frame = startFrame + index;
        this.beginFrame(frame);
        const requested = index === count - 1 ? lastRequested : _LZXDecoder.FRAME_SIZE;
        const physical = index === count - 1 ? lastPhysical : _LZXDecoder.FRAME_SIZE;
        const decoded = this.readFrame(
          new LZXBitReader(bytes),
          physical,
          frame,
          lastFrameSize === void 0
        );
        index++;
        yield decoded.subarray(0, requested);
      }
      if (index !== count)
        throw new Error("LZX frame count does not match output size");
    } finally {
      this.reset();
    }
  }
  /** Clear all stream state, including the dictionary and delta code lengths. */
  reset() {
    this.window.reset();
    this.mainLengths.fill(0);
    this.lengthLengths.fill(0);
    this.mainTree = this.lengthTree = this.alignedTree = null;
    this.recentOffsets = [1, 1, 1];
    this.headerRead = false;
    this.intelFileSize = 0;
    this.intelStarted = false;
    this.blockType = 0;
    this.blockRemaining = 0;
    this.oddRawPadding = false;
    this.historySize = 0;
  }
  validate() {
    return Number.isInteger(this.windowSize) && this.windowSize >= 32768 && this.windowSize <= 2097152 && Number.isInteger(Math.log2(this.windowSize)) && Number.isSafeInteger(this.resetInterval) && this.resetInterval > 0 && this.resetInterval % _LZXDecoder.FRAME_SIZE === 0;
  }
  getStatus() {
    return [
      `\u7A97\u53E3\u5927\u5C0F: ${this.windowSize} \u5B57\u8282`,
      `\u91CD\u7F6E\u95F4\u9694: ${this.resetInterval} \u5B57\u8282`,
      this.window.getStatus()
    ].join("\n");
  }
  checkOutputSize(size) {
    if (!Number.isSafeInteger(size) || size < 0 || size > _LZXDecoder.MAX_OUTPUT_SIZE) {
      throw new Error(
        `Invalid LZX output size (maximum ${_LZXDecoder.MAX_OUTPUT_SIZE} bytes)`
      );
    }
  }
  beginFrame(frame) {
    if (frame % (this.resetInterval / _LZXDecoder.FRAME_SIZE) === 0) {
      if (this.blockRemaining !== 0)
        throw new Error("LZX block crosses a reset boundary");
      this.reset();
    }
  }
  readFrame(reader, size, frame, allowPrefixMatch = true) {
    if (!this.headerRead) {
      if (reader.read(1)) {
        this.intelFileSize = reader.read(16) * 65536 + reader.read(16) | 0;
      }
      this.headerRead = true;
    }
    const output = import_buffer.Buffer.alloc(size);
    let position = 0;
    while (position < size) {
      if (this.blockRemaining === 0) this.readBlockHeader(reader);
      if (this.blockType === 3) {
        const count = Math.min(this.blockRemaining, size - position);
        const bytes = reader.readRaw(count);
        output.set(bytes, position);
        for (const byte of bytes) this.writeByte(byte);
        position += count;
        this.blockRemaining -= count;
        continue;
      }
      const symbol = this.mainTree.decode(reader);
      if (symbol < 256) {
        output[position++] = symbol;
        this.writeByte(symbol);
        this.blockRemaining--;
      } else {
        const { offset, length } = this.readMatch(reader, symbol);
        const frameLimit = allowPrefixMatch ? _LZXDecoder.FRAME_SIZE : size;
        if (length > this.blockRemaining || length > frameLimit - position) {
          throw new Error("LZX match exceeds block or frame boundary");
        }
        if (offset <= 0 || offset > this.historySize) {
          throw new Error("LZX match offset exceeds available history");
        }
        for (let i = 0; i < length; i++) {
          const byte = this.window.readBackByte(offset);
          if (position < size) output[position] = byte;
          position++;
          this.writeByte(byte);
        }
        this.blockRemaining -= length;
      }
    }
    reader.alignFrame();
    if (this.blockRemaining === 0 && this.oddRawPadding && reader.remainingBytes > 0) {
      reader.readRaw(1);
      this.oddRawPadding = false;
    }
    this.translateIntel(output, frame);
    return output;
  }
  writeByte(byte) {
    this.window.writeByte(byte);
    this.historySize = Math.min(this.windowSize, this.historySize + 1);
  }
  readBlockHeader(reader) {
    if (this.oddRawPadding) {
      reader.readRaw(1);
      this.oddRawPadding = false;
    }
    this.blockType = reader.read(3);
    this.blockRemaining = reader.read(16) * 256 + reader.read(8);
    if (this.blockRemaining === 0) throw new Error("Zero-length LZX block");
    if (this.blockType === 3) {
      this.intelStarted = true;
      reader.alignUncompressed();
      this.recentOffsets = [
        reader.readUInt32LE(),
        reader.readUInt32LE(),
        reader.readUInt32LE()
      ];
      if (this.recentOffsets.some(
        (offset) => offset === 0 || offset > this.windowSize
      )) {
        throw new Error("Invalid LZX uncompressed repeated offset");
      }
      this.oddRawPadding = (this.blockRemaining & 1) !== 0;
      return;
    }
    if (this.blockType !== 1 && this.blockType !== 2) {
      throw new Error(`Invalid LZX block type: ${this.blockType}`);
    }
    this.alignedTree = this.blockType === 2 ? new CanonicalTree(Array.from({ length: 8 }, () => reader.read(3))) : null;
    this.readLengths(reader, this.mainLengths, 0, 256);
    this.readLengths(reader, this.mainLengths, 256, this.mainLengths.length);
    this.mainTree = new CanonicalTree(this.mainLengths);
    if (this.mainLengths[232] !== 0) this.intelStarted = true;
    this.readLengths(reader, this.lengthLengths, 0, 249);
    this.lengthTree = new CanonicalTree(this.lengthLengths, true);
  }
  readLengths(reader, lengths, first, end) {
    const pretree = new CanonicalTree(
      Array.from({ length: 20 }, () => reader.read(4))
    );
    let position = first;
    while (position < end) {
      const symbol = pretree.decode(reader);
      if (symbol <= 16) {
        lengths[position] = (lengths[position] - symbol + 17) % 17;
        position++;
        continue;
      }
      let count;
      let value = 0;
      if (symbol === 17) {
        count = reader.read(4) + 4;
      } else if (symbol === 18) {
        count = reader.read(5) + 20;
      } else {
        count = reader.read(1) + 4;
        const delta = pretree.decode(reader);
        if (delta > 16)
          throw new Error("Invalid LZX repeated code-length delta");
        value = (lengths[position] - delta + 17) % 17;
      }
      if (count > end - position)
        throw new Error("LZX code-length run exceeds tree range");
      lengths.fill(value, position, position + count);
      position += count;
    }
  }
  readMatch(reader, symbol) {
    const match = symbol - 256;
    const slot = Math.floor(match / 8);
    let length = match & 7;
    if (length === 7) length += this.lengthTree.decode(reader);
    length += 2;
    let offset;
    if (slot < 3) {
      offset = this.recentOffsets[slot];
      if (slot !== 0) {
        this.recentOffsets[slot] = this.recentOffsets[0];
        this.recentOffsets[0] = offset;
      }
    } else {
      const extra = this.extraBits[slot];
      offset = this.positionBases[slot] - 2;
      if (this.blockType === 2 && extra >= 3) {
        offset += reader.read(extra - 3) * 8 + this.alignedTree.decode(reader);
      } else {
        offset += reader.read(extra);
      }
      this.recentOffsets = [
        offset,
        this.recentOffsets[0],
        this.recentOffsets[1]
      ];
    }
    return { offset, length };
  }
  translateIntel(output, frame) {
    const frameInReset = frame % (this.resetInterval / _LZXDecoder.FRAME_SIZE);
    if (!this.intelStarted || !this.intelFileSize || frameInReset >= 32768 || output.length <= 10)
      return;
    const framePosition = frameInReset * _LZXDecoder.FRAME_SIZE;
    for (let i = 0; i < output.length - 10; i++) {
      if (output[i] !== 232) continue;
      const position = framePosition + i;
      const absolute = output.readInt32LE(i + 1);
      if (absolute >= -position && absolute < this.intelFileSize) {
        const relative = absolute >= 0 ? absolute - position : absolute + this.intelFileSize;
        output.writeInt32LE(relative | 0, i + 1);
      }
      i += 4;
    }
  }
};
_LZXDecoder.FRAME_SIZE = 32768;
// A corrupt size must not cause an eager multi-gigabyte allocation. Large
// resources can be reconstructed in independent reset-aligned batches.
_LZXDecoder.MAX_OUTPUT_SIZE = 256 * 1024 * 1024;
_LZXDecoder.ALIGNED_NUM_ELEMENTS = 8;
var LZXDecoder = _LZXDecoder;

// src/core/files/file-manager.ts
init_browser_buffer();

// src/utils/helpers.ts
init_browser_buffer();
function filterFiles(files, pattern) {
  const regex = globToRegExp(pattern);
  return files.filter((file) => regex.test(file));
}
function globToRegExp(pattern) {
  const rooted = pattern.includes("/");
  const glob = rooted ? pattern.replace(/^\/+/, "") : pattern;
  let source = rooted ? "^/?" : "(?:^|/)";
  for (let i = 0; i < glob.length; i++) {
    const char = glob[i];
    if (char === "*") {
      if (glob[i + 1] === "*") {
        while (glob[i + 1] === "*") i++;
        if (glob[i + 1] === "/") {
          source += "(?:.*/)?";
          i++;
        } else {
          source += ".*";
        }
      } else {
        source += "[^/]*";
      }
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += /[\\^$.*+?()[\]{}|]/.test(char) ? `\\${char}` : char;
    }
  }
  return new RegExp(`${source}$`, "i");
}

// src/core/files/file-manager.ts
var CHMFileManager = class {
  constructor(parsedCHM) {
    this.parsedCHM = parsedCHM;
  }
  /**
   * 检查文件是否存在
   * @param fileName 文件名
   * @returns 是否存在
   */
  fileExists(fileName) {
    return this.findFileEntry(fileName) !== null;
  }
  /**
   * 获取文件信息（不读取内容）
   * @param fileName 文件名
   * @returns 文件信息
   */
  getFileInfo(fileName) {
    return this.findFileEntry(fileName);
  }
  /**
   * 获取所有文件列表
   * @returns 文件名数组
   */
  getFileList() {
    return Array.from(this.parsedCHM.directory.entries.keys());
  }
  /** User-visible files only; keep getFileList available for internal streams. */
  getUserFileList() {
    return this.getFileList().filter((name) => {
      const relative = name.replace(/^\/+/, "");
      return relative.length > 0 && !/[\\/]$/.test(name) && !/^::dataspace(?:\/|$)/i.test(relative) && !/^[#$]/.test(relative);
    });
  }
  /**
   * 按类型过滤文件
   * @param extension 文件扩展名
   * @returns 过滤后的文件名数组
   */
  getFilesByType(extension) {
    const normalizedExt = extension.toLowerCase();
    return this.getFileList().filter(
      (fileName) => fileName.toLowerCase().endsWith(normalizedExt)
    );
  }
  /**
   * 查找文件条目
   * @param fileName 文件名
   * @returns 文件条目
   */
  findFileEntry(fileName) {
    let entry = this.parsedCHM.directory.entries.get(fileName);
    if (entry) {
      return entry;
    }
    const normalizedName = this.normalizePath(fileName);
    entry = this.parsedCHM.directory.entries.get(normalizedName);
    if (entry) {
      return entry;
    }
    for (const [entryName, entryData] of this.parsedCHM.directory.entries) {
      if (this.normalizePath(entryName).toLowerCase() === normalizedName.toLowerCase()) {
        return entryData;
      }
    }
    return null;
  }
  /**
   * 标准化文件路径
   * @param path 原始路径
   * @returns 标准化后的路径
   */
  normalizePath(path) {
    path = path.replace(/\\/g, "/");
    if (!path.startsWith("/")) {
      path = `/${path}`;
    }
    path = path.replace(/\/+/g, "/");
    return path;
  }
  /**
   * 获取文件扩展名
   * @param fileName 文件名
   * @returns 扩展名
   */
  getFileExtension(fileName) {
    const lastDot = fileName.lastIndexOf(".");
    if (lastDot === -1) {
      return "\u65E0\u6269\u5C55\u540D";
    }
    return fileName.substring(lastDot + 1).toLowerCase();
  }
  /**
   * 按模式搜索文件
   * @param pattern 搜索模式（支持通配符 *）
   * @returns 匹配的文件名数组
   */
  searchFiles(pattern) {
    return filterFiles(this.getFileList(), pattern);
  }
  /**
   * 获取目录结构
   * @returns 目录结构映射
   */
  getDirectoryStructure() {
    const structure = /* @__PURE__ */ new Map();
    for (const fileName of this.getFileList()) {
      const dir = fileName.substring(0, fileName.lastIndexOf("/")) || "/";
      const files = structure.get(dir) || [];
      files.push(fileName);
      structure.set(dir, files);
    }
    return structure;
  }
};

// src/core/files/file-reconstructor.ts
var FileReconstructor = class {
  constructor(parsedCHM, options = {}) {
    this.parsedCHM = parsedCHM;
    this.cache = /* @__PURE__ */ new Map();
    this.cacheBytes = 0;
    this.hits = 0;
    this.misses = 0;
    this.fileManager = new CHMFileManager(parsedCHM);
    this.maxOutputBytes = options.maxOutputBytes ?? LZXDecoder.MAX_OUTPUT_SIZE;
    if (!Number.isSafeInteger(this.maxOutputBytes) || this.maxOutputBytes < 0)
      throw new Error("maxOutputBytes must be a non-negative safe integer");
    this.maxCacheBytes = 0;
    this.setCacheLimit(options.maxCacheBytes ?? 8 * 1024 * 1024);
  }
  reconstructFile(fileName, reader) {
    const entry = this.requireEntry(fileName);
    const data = this.reconstructRange(fileName, reader);
    return {
      name: entry.name,
      data,
      isCompressed: entry.section === 1,
      originalSize: entry.length,
      compressedSize: entry.section === 1 ? null : entry.length
    };
  }
  reconstructRange(fileName, reader, start = 0, end) {
    asByteSource(reader).validate?.();
    const entry = this.requireEntry(fileName);
    const limit = end ?? entry.length;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(limit) || start < 0 || limit < start || limit > entry.length) {
      throw new RangeError(
        `Invalid file range [${start}, ${limit}) for ${entry.name}`
      );
    }
    const length = limit - start;
    if (length > this.maxOutputBytes)
      throw new RangeError(
        "Requested output exceeds maxOutputBytes; use a range or stream"
      );
    if (length === 0) return import_buffer.Buffer.alloc(0);
    if (entry.section === 0) {
      const itsf = this.parsedCHM.header.itsf;
      const base = itsf.version === 3 ? itsf.unknown4 : checkedEnd(
        itsf.directoryOffset,
        itsf.directoryLength,
        "ITSF data base"
      );
      const absolute = checkedEnd(
        checkedEnd(base, entry.offset, entry.name),
        start,
        entry.name
      );
      const source = asByteSource(reader);
      requireSourceRange(source, absolute, length, entry.name);
      return import_buffer.Buffer.from(source.read(absolute, length));
    }
    if (entry.section !== 1)
      throw new Error(`Unsupported CHM section: ${entry.section}`);
    const table = this.parsedCHM.resetTable;
    const frameSize = table.blockSize;
    const resetBytes = this.parsedCHM.header.lzxc.resetInterval;
    if (frameSize !== LZXDecoder.FRAME_SIZE || !Number.isSafeInteger(resetBytes) || resetBytes <= 0 || resetBytes % frameSize !== 0 || resetBytes > LZXDecoder.MAX_OUTPUT_SIZE)
      throw new Error("Invalid or excessively large LZX reset interval");
    const absoluteStart = checkedEnd(entry.offset, start, entry.name);
    const absoluteEnd = checkedEnd(entry.offset, limit, entry.name);
    if (absoluteEnd > table.uncompressedLength)
      throw new Error(`File range exceeds LZX stream: ${entry.name}`);
    const output = import_buffer.Buffer.alloc(length);
    let written = 0;
    for (let group = Math.floor(absoluteStart / resetBytes) * resetBytes; group < absoluteEnd; group += resetBytes) {
      const groupSize = Math.min(resetBytes, table.uncompressedLength - group);
      if (groupSize > this.maxCacheBytes) {
        this.misses++;
        const from2 = Math.max(absoluteStart, group) - entry.offset;
        const to2 = Math.min(absoluteEnd, group + groupSize) - entry.offset;
        for (const chunk of this.iterateFileChunks(
          fileName,
          reader,
          64 * 1024,
          from2,
          to2
        )) {
          chunk.copy(output, written);
          written += chunk.length;
        }
        continue;
      }
      const data = this.readResetGroup(group, reader);
      const from = Math.max(absoluteStart, group) - group;
      const to = Math.min(absoluteEnd, group + data.length) - group;
      if (to <= from)
        throw new Error("LZX reset group does not cover requested bytes");
      data.copy(output, written, from, to);
      written += to - from;
    }
    if (written !== length) throw new Error("Incomplete file reconstruction");
    return output;
  }
  /**
   * Sequential, cache-independent reconstruction of a file-relative [start, end)
   * range (default: the whole file). Each physical frame from the nearest reset
   * before start through the range end is decoded once, including any prefix
   * needed for history and the last frame's physical Intel E8 tail. Returned
   * buffers are owned copies, at most min(chunkSize, maxOutputBytes) bytes.
   * Validation/I/O is lazy; callers must exhaust or return() the generator to
   * release its decoder and source references. The reader cursor is unchanged.
   */
  *iterateFileChunks(fileName, reader, chunkSize, start = 0, end) {
    if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0)
      throw new RangeError("chunkSize must be a positive safe integer");
    const source = asByteSource(reader);
    source.validate?.();
    const entry = this.requireEntry(fileName);
    const until = end ?? entry.length;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(until) || start < 0 || until < start || until > entry.length)
      throw new RangeError(
        `Invalid file range [${start}, ${until}) for ${entry.name}`
      );
    const length = until - start;
    if (length === 0) return;
    if (entry.section !== 0 && entry.section !== 1)
      throw new Error(`Unsupported CHM section: ${entry.section}`);
    const absoluteStart = checkedEnd(entry.offset, start, entry.name);
    const absoluteEnd = checkedEnd(entry.offset, until, entry.name);
    if (this.maxOutputBytes === 0)
      throw new RangeError("Requested output exceeds maxOutputBytes");
    const limit = Math.min(chunkSize, this.maxOutputBytes);
    if (entry.section === 0) {
      const itsf = this.parsedCHM.header.itsf;
      const base = itsf.version === 3 ? itsf.unknown4 : checkedEnd(
        itsf.directoryOffset,
        itsf.directoryLength,
        "ITSF data base"
      );
      const absolute = checkedEnd(base, absoluteStart, entry.name);
      const source2 = asByteSource(reader);
      requireSourceRange(source2, absolute, length, entry.name);
      for (let position = 0; position < length; ) {
        const size = Math.min(limit, length - position);
        yield import_buffer.Buffer.from(source2.read(absolute + position, size));
        position += size;
      }
      return;
    }
    const table = this.parsedCHM.resetTable;
    const frameSize = LZXDecoder.FRAME_SIZE;
    const resetBytes = this.parsedCHM.header.lzxc.resetInterval;
    if (table.blockSize !== frameSize || !Number.isSafeInteger(resetBytes) || resetBytes <= 0 || resetBytes % frameSize !== 0)
      throw new Error("Invalid LZX reset interval or frame size");
    if (absoluteEnd > checkedEnd(table.uncompressedLength, 0, "LZX stream"))
      throw new Error(`File range exceeds LZX stream: ${entry.name}`);
    const startFrame = Math.floor(absoluteStart / resetBytes) * resetBytes / frameSize;
    const endFrame = Math.ceil(absoluteEnd / frameSize);
    const compressed = this.iterateCompressedFrames(
      reader,
      startFrame,
      endFrame
    );
    yield* this.iterateDecodedChunks(
      new LZXDecoder(this.parsedCHM.header.lzxc).iterateFrames(
        compressed,
        absoluteEnd - startFrame * frameSize,
        startFrame,
        frameSize
      ),
      source,
      absoluteStart - startFrame * frameSize,
      length,
      limit
    );
  }
  *iterateDecodedChunks(decoded, source, skip, remaining, limit) {
    let chunk;
    let filled = 0;
    const takeChunk = () => {
      const ready = chunk;
      chunk = void 0;
      filled = 0;
      return ready;
    };
    for (const frame of decoded) {
      let position = Math.min(skip, frame.length);
      skip -= position;
      while (position < frame.length) {
        chunk ?? (chunk = import_buffer.Buffer.alloc(Math.min(limit, remaining)));
        const count = Math.min(chunk.length - filled, frame.length - position);
        frame.copy(chunk, filled, position, position + count);
        filled += count;
        position += count;
        remaining -= count;
        if (filled === chunk.length) {
          source.validate?.();
          yield takeChunk();
        }
      }
    }
    if (remaining !== 0) throw new Error("Incomplete file reconstruction");
  }
  *iterateCompressedFrames(reader, start, end) {
    for (let index = start; index < end; index++)
      yield this.readCompressedFrame(index, reader);
  }
  readCompressedFrame(index, reader) {
    const table = this.parsedCHM.resetTable;
    const offset = table.entries[index]?.compressedLength;
    const next = table.entries[index + 1]?.compressedLength ?? table.compressedLength;
    if (offset === void 0 || !Number.isSafeInteger(offset) || !Number.isSafeInteger(next) || offset < 0 || next <= offset || next > table.compressedLength)
      throw new Error(`Invalid LZX frame offsets at ${index}`);
    const absolute = checkedEnd(
      this.parsedCHM.contentOffset,
      offset,
      "LZX frame"
    );
    const source = asByteSource(reader);
    requireSourceRange(source, absolute, next - offset, "LZX frame");
    return source.read(absolute, next - offset);
  }
  readResetGroup(group, reader) {
    const cached = this.cache.get(group);
    if (cached) {
      this.hits++;
      this.cache.delete(group);
      this.cache.set(group, cached);
      return cached;
    }
    this.misses++;
    const table = this.parsedCHM.resetTable;
    const size = Math.min(
      this.parsedCHM.header.lzxc.resetInterval,
      table.uncompressedLength - group
    );
    if (size <= 0) throw new Error("LZX reset group is outside the stream");
    const startFrame = group / LZXDecoder.FRAME_SIZE;
    const frameCount = Math.ceil(size / LZXDecoder.FRAME_SIZE);
    const frames = this.iterateCompressedFrames(
      reader,
      startFrame,
      startFrame + frameCount
    );
    const data = import_buffer.Buffer.alloc(size);
    let position = 0;
    for (const frame of new LZXDecoder(
      this.parsedCHM.header.lzxc
    ).iterateFrames(frames, size, startFrame, LZXDecoder.FRAME_SIZE)) {
      frame.copy(data, position);
      position += frame.length;
    }
    if (position !== size) throw new Error("Incomplete LZX reset group");
    if (data.length <= this.maxCacheBytes) {
      this.cache.set(group, data);
      this.cacheBytes += data.length;
      this.evict();
    }
    return data;
  }
  reconstructFiles(fileNames, reader) {
    return new Map(
      fileNames.map((name) => [name, this.reconstructFile(name, reader)])
    );
  }
  reconstructAllFiles(reader) {
    return this.reconstructFiles(this.fileManager.getFileList(), reader);
  }
  validateFile(file) {
    return import_buffer.Buffer.isBuffer(file.data) && file.data.length === file.originalSize;
  }
  clearCache() {
    this.cache.clear();
    this.cacheBytes = 0;
    this.hits = this.misses = 0;
  }
  setCacheLimit(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0)
      throw new RangeError("Cache limit must be a non-negative safe integer");
    this.maxCacheBytes = bytes;
    this.evict();
  }
  getCacheStats() {
    return {
      entries: this.cache.size,
      bytes: this.cacheBytes,
      hits: this.hits,
      misses: this.misses,
      maxBytes: this.maxCacheBytes
    };
  }
  evict() {
    while (this.cacheBytes > this.maxCacheBytes && this.cache.size > 0) {
      const key = this.cache.keys().next().value;
      this.cacheBytes -= this.cache.get(key).length;
      this.cache.delete(key);
    }
  }
  requireEntry(name) {
    const entry = this.fileManager.findFileEntry(name);
    if (!entry) throw new Error(`\u6587\u4EF6\u672A\u627E\u5230: ${name}`);
    return entry;
  }
};

// src/reader/types.ts
init_browser_buffer();
var CacheStrategy = {
  None: "none",
  LRU: "lru"
};

// src/reader/reader-utils.ts
init_browser_buffer();
var ENTITIES = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: "\xA0",
  copy: "\xA9",
  reg: "\xAE",
  trade: "\u2122",
  hellip: "\u2026",
  ndash: "\u2013",
  mdash: "\u2014",
  lsquo: "\u2018",
  rsquo: "\u2019",
  ldquo: "\u201C",
  rdquo: "\u201D",
  bull: "\u2022",
  middot: "\xB7",
  laquo: "\xAB",
  raquo: "\xBB",
  ensp: "\u2002",
  emsp: "\u2003"
};
var LATIN_ENTITIES = "nbsp iexcl cent pound curren yen brvbar sect uml copy ordf laquo not shy reg macr deg plusmn sup2 sup3 acute micro para middot cedil sup1 ordm raquo frac14 frac12 frac34 iquest Agrave Aacute Acirc Atilde Auml Aring AElig Ccedil Egrave Eacute Ecirc Euml Igrave Iacute Icirc Iuml ETH Ntilde Ograve Oacute Ocirc Otilde Ouml times Oslash Ugrave Uacute Ucirc Uuml Yacute THORN szlig agrave aacute acirc atilde auml aring aelig ccedil egrave eacute ecirc euml igrave iacute icirc iuml eth ntilde ograve oacute ocirc otilde ouml divide oslash ugrave uacute ucirc uuml yacute thorn yuml".split(" ");
LATIN_ENTITIES.forEach((name, index) => {
  ENTITIES[name] = String.fromCharCode(160 + index);
});
function lookup(map, key) {
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : void 0;
}
function decodeEntities(text) {
  return text.replace(
    /&(#x[\da-f]+|#\d+|[a-z][\da-z]+);/gi,
    (original, entity) => {
      if (!entity.startsWith("#"))
        return lookup(ENTITIES, entity) ?? lookup(ENTITIES, entity.toLowerCase()) ?? original;
      const hex = entity[1]?.toLowerCase() === "x";
      const code = Number.parseInt(entity.slice(hex ? 2 : 1), hex ? 16 : 10);
      return code > 0 && code <= 1114111 && !(code >= 55296 && code <= 57343) ? String.fromCodePoint(code) : "\uFFFD";
    }
  );
}
function attributes(tag) {
  const result = /* @__PURE__ */ Object.create(null);
  const expression = /([^\s=<>/]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
  for (const match of tag.matchAll(expression)) {
    result[match[1].toLowerCase()] = decodeEntities(
      match[2] ?? match[3] ?? match[4]
    );
  }
  return result;
}
function normalizePath(path) {
  if (typeof path !== "string" || path.includes("\0"))
    throw new Error("Invalid CHM path");
  const source = path.replace(/\\/g, "/");
  const internal = source.replace(/^\/+/, "").startsWith("::");
  const parts = [];
  for (const part of source.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (!parts.length)
        throw new Error(`CHM path escapes archive root: ${path}`);
      parts.pop();
    } else parts.push(part);
  }
  const normalized = `${internal ? "" : "/"}${parts.join("/")}`;
  return source.endsWith("/") && parts.length ? `${normalized}/` : normalized;
}
function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function globExpression(pattern) {
  const source = pattern.replace(/\\/g, "/").replace(/^\/+/, "");
  let regex = "";
  let braceDepth = 0;
  for (let i = 0; i < source.length; i++) {
    const character = source[i];
    if (character === "*") {
      if (source[i + 1] === "*") {
        i++;
        if (source[i + 1] === "/") {
          regex += "(?:.*/)?";
          i++;
        } else regex += ".*";
      } else regex += "[^/]*";
    } else if (character === "?") regex += "[^/]";
    else if (character === "[") {
      const end = source.indexOf("]", i + 1);
      const content = source.slice(i + 1, end);
      if (end > i + 1 && !/[\\[]/.test(content)) {
        const body = content.startsWith("!") ? `^${content.slice(1)}` : content;
        regex += `(?!/)[${body}]`;
        i = end;
      } else regex += "\\[";
    } else if (character === "{") {
      regex += "(?:";
      braceDepth++;
    } else if (character === "}" && braceDepth) {
      regex += ")";
      braceDepth--;
    } else if (character === "," && braceDepth) regex += "|";
    else regex += escapeRegExp(character);
  }
  if (braceDepth) throw new Error(`Unclosed brace in glob: ${pattern}`);
  try {
    return new RegExp(`^${regex}$`, "i");
  } catch {
    throw new Error(`Invalid glob: ${pattern}`);
  }
}
function encodingLabel(encoding) {
  const lower = encoding.toLowerCase().replace(/[_-]/g, "");
  const aliases = {
    utf8: "utf-8",
    utf16le: "utf-16le",
    ucs2: "utf-16le",
    utf16be: "utf-16be",
    binary: "windows-1252",
    latin1: "windows-1252"
  };
  return lookup(aliases, lower) ?? encoding;
}
function languageEncoding(languageId) {
  if ((languageId & 1023) === 4)
    return [1028, 3076, 5124].includes(languageId & 65535) ? "big5" : "gbk";
  if ((languageId & 1023) === 17) return "shift_jis";
  if ((languageId & 1023) === 18) return "euc-kr";
  if ((languageId & 1023) === 25) return "windows-1251";
  return "windows-1252";
}
function decodeText(data, encoding, fallback = "windows-1252") {
  let label = encoding;
  if (data[0] === 239 && data[1] === 187 && data[2] === 191) label = "utf-8";
  else if (data[0] === 255 && data[1] === 254) label = "utf-16le";
  else if (data[0] === 254 && data[1] === 255) label = "utf-16be";
  if (!label) {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(data);
    } catch {
      label = fallback;
    }
  }
  return new TextDecoder(encodingLabel(label)).decode(data).replace(/^\ufeff/, "");
}
function htmlEncoding(data) {
  const head = data.subarray(0, 4096).toString("latin1");
  for (const tag of head.match(/<meta\b[^>]*>/gi) ?? []) {
    const attr = attributes(tag);
    if (attr.charset) return attr.charset.trim();
    const charset = attr.content?.match(/charset\s*=\s*([^\s;"']+)/i)?.[1];
    if (charset) return charset;
  }
  return void 0;
}
var MIME = {
  html: "text/html",
  htm: "text/html",
  hhc: "text/html",
  hhk: "text/html",
  txt: "text/plain",
  md: "text/markdown",
  css: "text/css",
  js: "text/javascript",
  mjs: "text/javascript",
  json: "application/json",
  xml: "application/xml",
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  ico: "image/x-icon",
  bmp: "image/bmp",
  pdf: "application/pdf",
  woff: "font/woff",
  woff2: "font/woff2",
  ttf: "font/ttf",
  mp3: "audio/mpeg",
  wav: "audio/wav",
  mp4: "video/mp4",
  zip: "application/zip"
};
function mimeType(path) {
  return lookup(MIME, /\.([^./]+)$/.exec(path)?.[1].toLowerCase() ?? "") ?? "application/octet-stream";
}

// src/reader/navigation.ts
init_browser_buffer();
var TAGS = /<!--[\s\S]*?-->|<(?:"[^"]*"|'[^']*'|[^'">])*>/g;
function parseSitemap(html, resolve) {
  const roots = [];
  const stack = [roots];
  let pending;
  function commit() {
    if (!pending) return;
    if (pending.name || pending.local) {
      stack[stack.length - 1].push({
        name: pending.name ?? pending.local,
        local: pending.local ? resolve(pending.local) : "",
        level: 0
      });
    }
    pending = void 0;
  }
  const source = html.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, "");
  for (const match of source.matchAll(TAGS)) {
    const tag = match[0];
    if (tag.startsWith("<!--")) continue;
    const name = /^<\s*(\/?\w+)/.exec(tag)?.[1].toLowerCase();
    if (name === "object") {
      commit();
      const type = attributes(tag).type;
      if (!type || type.toLowerCase() === "text/sitemap")
        pending = /* @__PURE__ */ Object.create(null);
    } else if (name === "param" && pending) {
      const attr = attributes(tag);
      if (attr.name && attr.value !== void 0)
        pending[attr.name.toLowerCase()] = attr.value;
    } else if (name === "/object" || name === "li" || name === "/li") commit();
    else if (name === "ul") {
      commit();
      const current = stack[stack.length - 1];
      const parent = current[current.length - 1];
      if (parent) {
        parent.children ?? (parent.children = []);
        stack.push(parent.children);
      } else stack.push(current);
    } else if (name === "/ul") {
      commit();
      if (stack.length > 1) stack.pop();
    }
  }
  commit();
  const queue = roots.map((node) => ({ node, level: 0 }));
  for (let i = 0; i < queue.length; i++) {
    const { node, level } = queue[i];
    node.level = level;
    for (const child of node.children ?? [])
      queue.push({ node: child, level: level + 1 });
  }
  return roots;
}
function parseLinks(html, resolve) {
  const result = [];
  const source = html.replace(
    /<!--[\s\S]*?-->|<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,
    ""
  );
  const expression = /<a\b((?:"[^"]*"|'[^']*'|[^'">])*)>([\s\S]*?)<\/a\s*>|<link\b((?:"[^"]*"|'[^']*'|[^'">])*)>/gi;
  for (const match of source.matchAll(expression)) {
    const attr = attributes(match[1] ?? match[3]);
    if (!attr.href || /^(?:javascript|data|vbscript):/i.test(attr.href.trim()))
      continue;
    result.push({
      name: decodeEntities((match[2] ?? "").replace(/<[^>]*>/g, "")).trim() || attr.title || attr.rel || attr.href,
      href: attr.href,
      local: resolve(attr.href),
      ...attr.rel ? { rel: attr.rel } : {}
    });
  }
  return result;
}

// src/reader/chm-archive.ts
var DEFAULT_CACHE_BYTES = 8 * 1024 * 1024;
var DEFAULT_FILE_SIZE = 256 * 1024 * 1024;
var STREAM_CHUNK_BYTES = 64 * 1024;
var MAX_DIRECTORY_DEPTH = 1024;
var MAX_DIRECTORY_COUNT = 1e5;
var MAX_DIRECTORY_PATH_CHARS = 8 * 1024 * 1024;
function isInternalPath(path) {
  const relative = normalizePath(path).replace(/^\/+/, "");
  return /^[#$]/.test(relative) || /^::dataspace(?:\/|$)/i.test(relative);
}
function nonnegative(value, name) {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new RangeError(`${name} must be a non-negative safe integer`);
  return value;
}
var CHMArchive = class {
  /** A byte source transfers ownership, including close(), even if parsing fails. */
  constructor(input, options = {}) {
    this.activeStreams = /* @__PURE__ */ new Set();
    this.paths = /* @__PURE__ */ new Map();
    this.cache = /* @__PURE__ */ new Map();
    this.cacheBytes = 0;
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.preloadOrder = [];
    this.preloadIndices = /* @__PURE__ */ new Map();
    this.preloadQueue = [];
    this.preloadPrevious = -1;
    this.preloadTransitions = 0;
    this.source = input instanceof Uint8Array || input instanceof ArrayBuffer ? new MemoryByteSource(
      import_buffer.Buffer.from(
        input instanceof Uint8Array ? input : new Uint8Array(input)
      )
    ) : input;
    try {
      this.maxCacheBytes = nonnegative(
        options.maxCacheBytes ?? DEFAULT_CACHE_BYTES,
        "maxCacheBytes"
      );
      this.maxFileSize = nonnegative(
        options.maxFileSize ?? DEFAULT_FILE_SIZE,
        "maxFileSize"
      );
      this.defaultEncoding = options.defaultEncoding;
      this.strategy = options.cacheStrategy ?? CacheStrategy.LRU;
      this.validateStrategy(this.strategy);
      if (options.readAhead !== void 0 && typeof options.readAhead !== "boolean")
        throw new TypeError("readAhead must be a boolean");
      if (options.adaptivePreload !== void 0) {
        const config = options.adaptivePreload;
        if (!config || typeof config !== "object" || Array.isArray(config))
          throw new TypeError("adaptivePreload must be an options object");
        nonnegative(config.maxFiles, "adaptivePreload.maxFiles");
        nonnegative(config.maxBytes, "adaptivePreload.maxBytes");
        if (config.maxFiles < 1 || config.maxFiles > 32 || config.maxBytes < 1)
          throw new RangeError(
            "adaptivePreload requires maxFiles in [1, 32] and positive maxBytes"
          );
        this.adaptivePreload = {
          maxFiles: config.maxFiles,
          maxBytes: config.maxBytes
        };
      }
      this.source.cache?.setReadAhead?.(options.readAhead ?? true);
      this.parsed = new CHMParser().parseSource(this.source);
      for (const entry of this.parsed.directory.entries.values()) {
        const key = normalizePath(entry.name).toLowerCase();
        if (this.paths.has(key))
          throw new Error(`Ambiguous case-insensitive CHM path: ${entry.name}`);
        this.paths.set(key, entry);
      }
      this.reconstructor = new FileReconstructor(this.parsed, {
        maxCacheBytes: this.blockCacheLimit(),
        maxOutputBytes: this.maxFileSize
      });
      this.source.cache?.setLimit(this.sourceCacheLimit());
      if (this.adaptivePreload) {
        const ordered = [...this.paths.values()].filter(
          (entry) => !entry.name.endsWith("/") && !isInternalPath(entry.name)
        ).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
        for (const entry of ordered) {
          this.preloadIndices.set(entry.name, this.preloadOrder.length);
          this.preloadOrder.push(entry);
        }
      }
    } catch (error) {
      this.source.close?.();
      this.source = void 0;
      throw error;
    }
  }
  isOpen() {
    return this.source !== void 0;
  }
  close() {
    try {
      for (const release of this.activeStreams) release();
      this.clearCache();
    } finally {
      const source = this.source;
      this.paths.clear();
      this.preloadOrder.length = 0;
      this.preloadIndices.clear();
      this.reconstructor = void 0;
      this.parsed = void 0;
      this.source = void 0;
      source?.close?.();
    }
  }
  listFiles(pattern) {
    this.assertOpen();
    const files = [...this.paths.values()].filter((entry) => !entry.name.endsWith("/") && !isInternalPath(entry.name)).map((entry) => entry.name).sort();
    if (pattern === void 0) return files;
    const expression = globExpression(pattern);
    return files.filter((name) => expression.test(name.replace(/^\/+/, "")));
  }
  listDirectories() {
    this.assertOpen();
    const directories = /* @__PURE__ */ new Map();
    let characters = 0;
    for (const entry of this.paths.values()) {
      if (isInternalPath(entry.name)) continue;
      const path = normalizePath(entry.name);
      if (path.split("/").length - 2 > MAX_DIRECTORY_DEPTH)
        throw new RangeError("CHM directory depth exceeds safety limit (1024)");
      for (let index = path.indexOf("/", path.startsWith("/") ? 1 : 0); index !== -1; index = path.indexOf("/", index + 1)) {
        const directoryKey = path.slice(0, index + 1).toLowerCase();
        if (directories.has(directoryKey)) continue;
        if (directories.size >= MAX_DIRECTORY_COUNT || characters + index + 1 > MAX_DIRECTORY_PATH_CHARS)
          throw new RangeError("CHM directory expansion exceeds safety limit");
        characters += index + 1;
        directories.set(directoryKey, path.slice(0, index + 1));
      }
    }
    return [...directories.values()].sort();
  }
  exists(path) {
    this.assertOpen();
    const key = normalizePath(path).toLowerCase();
    const directory = key.endsWith("/") ? key : `${key}/`;
    return key === "/" || this.paths.has(key) || this.paths.has(directory) || [...this.paths.keys()].some((name) => name.startsWith(directory));
  }
  getFileTree() {
    this.assertOpen();
    const root = {
      name: "/",
      path: "/",
      type: "directory",
      size: 0,
      children: []
    };
    const nodes = /* @__PURE__ */ new Map([["/", root]]);
    const addDirectory = (path) => {
      const key = path.toLowerCase();
      const existing = nodes.get(key);
      if (existing) return existing;
      const node = {
        name: path.replace(/\/$/, "").split("/").pop(),
        path,
        type: "directory",
        size: 0,
        children: []
      };
      nodes.set(key, node);
      return node;
    };
    for (const path of this.listDirectories().sort(
      (a, b) => a.length - b.length
    )) {
      const node = addDirectory(path);
      const parentPath = path.slice(0, -1).replace(/[^/]+$/, "");
      const parent = parentPath ? addDirectory(parentPath) : root;
      parent.children.push(node);
    }
    for (const path of this.listFiles()) {
      const entry = this.fileEntry(path);
      const parentPath = path.slice(0, path.lastIndexOf("/") + 1);
      const parent = nodes.get(parentPath.toLowerCase()) ?? root;
      parent.children.push({
        name: path.split("/").pop(),
        path,
        type: "file",
        size: this.entrySize(entry)
      });
    }
    return root;
  }
  glob(pattern) {
    return this.listFiles(pattern);
  }
  readFile(path) {
    const entry = this.fileEntry(path);
    const data = this.readEntry(entry);
    this.observePreloadAccess(entry);
    return data;
  }
  readEntry(entry, copyForCaller = true) {
    const size = this.entrySize(entry);
    this.checkOutputSize(size);
    const key = entry.name;
    const cached = this.cachedFile(key);
    if (cached) return copyForCaller ? import_buffer.Buffer.from(cached) : cached;
    this.cacheMisses++;
    const data = this.reconstruct(entry, 0, size);
    const limit = this.fileCacheLimit();
    if (this.strategy === CacheStrategy.LRU && data.length <= limit && limit > 0) {
      while (this.cacheBytes + data.length > limit) this.evictOldest();
      this.cache.set(key, data);
      this.cacheBytes += data.length;
      return copyForCaller ? import_buffer.Buffer.from(data) : data;
    }
    return data;
  }
  readText(path, encoding) {
    return this.decode(path, this.readFile(path), encoding);
  }
  readHTML(path, encoding) {
    const data = this.readFile(path);
    return this.decode(path, data, encoding ?? htmlEncoding(data));
  }
  readJSON(path, encoding) {
    const text = this.readText(path, encoding);
    try {
      return JSON.parse(text);
    } catch (error) {
      throw new SyntaxError(
        `Invalid JSON in CHM file "${path}": ${error instanceof Error ? error.message : String(error)}`,
        { cause: error }
      );
    }
  }
  readImage(path) {
    return this.readFile(path);
  }
  readCSS(path, encoding) {
    return this.readText(path, encoding);
  }
  readJS(path, encoding) {
    return this.readText(path, encoding);
  }
  /** Strict half-open [start, end); no clamping or negative-index surprises. */
  readRange(path, start = 0, end) {
    const entry = this.fileEntry(path);
    const size = this.entrySize(entry);
    const until = end ?? size;
    nonnegative(start, "range start");
    nonnegative(until, "range end");
    if (start > until || until > size)
      throw new RangeError(
        `Invalid range [${start}, ${until}) for "${entry.name}" (${size} bytes)`
      );
    this.checkOutputSize(until - start);
    const cached = this.cachedFile(entry.name);
    if (cached) return import_buffer.Buffer.from(cached.subarray(start, until));
    return this.reconstruct(entry, start, until);
  }
  /** Backpressured <=64-KiB pulls, reusing LZX state even with caching disabled. */
  createReadStream(path, start = 0, end) {
    const entry = this.fileEntry(path);
    const fileSize = this.entrySize(entry);
    const until = end ?? fileSize;
    nonnegative(start, "range start");
    nonnegative(until, "range end");
    if (start > until || until > fileSize)
      throw new RangeError(
        `Invalid range [${start}, ${until}) for "${entry.name}" (${fileSize} bytes)`
      );
    const size = until - start;
    if (size > 0 && this.maxFileSize === 0) this.checkOutputSize(1);
    const chunkSize = Math.max(
      1,
      Math.min(STREAM_CHUNK_BYTES, this.maxFileSize)
    );
    let iterator;
    let position = 0;
    let cancelled = false;
    const release = () => {
      this.activeStreams.delete(release);
      iterator?.return(void 0);
      iterator = void 0;
    };
    return new ReadableStream(
      {
        pull: (controller) => {
          if (cancelled) return;
          try {
            this.assertOpen();
            if (position === size) {
              controller.close();
              return;
            }
            iterator ?? (iterator = this.reconstructor.iterateFileChunks(
              entry.name,
              this.source,
              chunkSize,
              start,
              until
            ));
            this.activeStreams.add(release);
            const next = iterator.next();
            if (next.done || next.value.length === 0)
              throw new Error(
                `Incomplete CHM stream reconstruction: ${entry.name}`
              );
            position += next.value.length;
            if (position > size)
              throw new Error(`CHM stream exceeds file size: ${entry.name}`);
            controller.enqueue(next.value);
            if (position === size) {
              release();
              controller.close();
            }
          } catch (error) {
            release();
            controller.error(error);
          }
        },
        cancel: () => {
          cancelled = true;
          release();
        }
      },
      { highWaterMark: 0 }
    );
  }
  readMultiple(paths) {
    this.assertOpen();
    const result = /* @__PURE__ */ new Map();
    for (const path of paths) result.set(path, this.readFile(path));
    return result;
  }
  readWithMetadata(path) {
    const metadata = this.getFileInfo(path);
    return { ...metadata, data: this.readFile(path), metadata };
  }
  getFileInfo(path) {
    const entry = this.fileEntry(path);
    const size = this.entrySize(entry);
    const isCompressed = entry.section === 1;
    const compressedSize = isCompressed ? null : size;
    return {
      name: entry.name,
      path: entry.name,
      size,
      originalSize: size,
      isCompressed,
      compressedSize,
      compressedSizeExact: !isCompressed,
      compressionRatio: isCompressed ? null : size === 0 ? 0 : 1,
      ...isCompressed ? {
        compressionNote: "File belongs to a shared LZX stream; exact per-file compressed size and ratio are unavailable."
      } : {},
      mimeType: mimeType(entry.name),
      section: entry.section,
      offset: entry.offset
    };
  }
  getFileSize(path) {
    return this.entrySize(this.fileEntry(path));
  }
  getCompressedSize(path) {
    return this.getFileInfo(path).compressedSize;
  }
  /** compressed/original; null for shared compressed streams, 0 for an empty stored file. */
  getCompressionRatio(path) {
    return this.getFileInfo(path).compressionRatio;
  }
  getMimeType(path) {
    return mimeType(this.fileEntry(path).name);
  }
  getMetadata() {
    this.assertOpen();
    const entry = this.paths.get("/#system");
    if (!entry) return {};
    const data = this.readFile(entry.name);
    if (data.length < 4) throw new Error("Invalid /#SYSTEM: missing version");
    const records = [];
    let languageId = this.parsed.header.itsf.languageId;
    for (let offset = 4; offset < data.length; ) {
      if (offset + 4 > data.length)
        throw new Error("Invalid /#SYSTEM: truncated record header");
      const code = data.readUInt16LE(offset);
      const length = data.readUInt16LE(offset + 2);
      offset += 4;
      if (offset + length > data.length)
        throw new Error(`Invalid /#SYSTEM: truncated record ${code}`);
      const bytes = data.subarray(offset, offset + length);
      records.push({ code, bytes });
      if (code === 4 && length >= 4) languageId = bytes.readUInt32LE(0);
      offset += length;
    }
    const result = {};
    const names = ["toc", "index", "defaultTopic", "title"];
    for (const { code, bytes } of records) {
      if (code <= 3)
        result[names[code]] = decodeText(
          bytes,
          this.defaultEncoding,
          languageEncoding(languageId)
        ).replace(/\0[\s\S]*$/, "");
    }
    return result;
  }
  getTOC() {
    return this.readNavigation("toc", /\.hhc$/i);
  }
  getIndex() {
    return this.readNavigation("index", /\.hhk$/i);
  }
  getDefaultPage() {
    const metadata = this.getMetadata();
    if (metadata.defaultTopic)
      return this.resolveLink(metadata.defaultTopic, "/");
    const files = this.listFiles();
    return files.find((path) => /^\/index\.html?$/i.test(path)) ?? files.find((path) => /\.html?$/i.test(path));
  }
  getHomePage() {
    return this.getDefaultPage();
  }
  getNavigationLinks(path) {
    const entry = this.fileEntry(path);
    return parseLinks(
      this.readHTML(entry.name),
      (local) => this.resolveLink(local, entry.name)
    );
  }
  search(keyword, options = {}) {
    this.assertOpen();
    const limit = nonnegative(options.maxResults ?? 100, "maxResults");
    const matchesLimit = nonnegative(
      options.maxMatchesPerFile ?? 100,
      "maxMatchesPerFile"
    );
    if (!keyword || !limit || !matchesLimit) return [];
    const results = [];
    for (const path of this.listFiles(options.pattern)) {
      const mime = mimeType(path);
      if (!mime.startsWith("text/") && !["application/json", "application/xml", "image/svg+xml"].includes(mime))
        continue;
      const matches = this.searchInFile(path, keyword, {
        ...options,
        maxResults: matchesLimit
      });
      if (matches.length) results.push({ path, fileName: path, matches });
      if (results.length === limit) break;
    }
    return results;
  }
  searchInFile(path, keyword, options = {}) {
    this.fileEntry(path);
    const limit = nonnegative(options.maxResults ?? 100, "maxResults");
    const contextLength = nonnegative(
      options.contextLength ?? 80,
      "contextLength"
    );
    if (!keyword || !limit) return [];
    const text = /\.hh[ctk]$|\.html?$/i.test(path) ? this.readHTML(path, options.encoding) : this.readText(path, options.encoding);
    const escaped = escapeRegExp(keyword);
    const wordCharacters = "\\p{L}\\p{N}\\p{M}_";
    const expression = new RegExp(
      options.wholeWord ? `(?<![${wordCharacters}])${escaped}(?![${wordCharacters}])` : escaped,
      options.caseSensitive ? "gu" : "giu"
    );
    const matches = [];
    let line = 1;
    let lineStart = 0;
    let scanned = 0;
    for (const match of text.matchAll(expression)) {
      const index = match.index;
      for (; scanned < index; scanned++)
        if (text[scanned] === "\n") {
          line++;
          lineStart = scanned + 1;
        }
      matches.push({
        index,
        length: match[0].length,
        match: match[0],
        line,
        column: index - lineStart + 1,
        context: text.slice(
          Math.max(0, index - contextLength),
          index + match[0].length + contextLength
        )
      });
      if (matches.length === limit) break;
    }
    return matches;
  }
  /** Globs when wildcards are present; otherwise a case-insensitive path substring. */
  findFiles(pattern) {
    return /[*?{[]/.test(pattern) ? this.glob(pattern) : this.listFiles().filter(
      (path) => path.toLowerCase().includes(pattern.toLowerCase())
    );
  }
  /** Deterministic filename subsequence matching, not an AI/full-text index. */
  fuzzySearch(query, options = {}) {
    this.assertOpen();
    const limit = nonnegative(options.maxResults ?? 100, "maxResults");
    if (!query || !limit) return [];
    const needle = Array.from(
      options.caseSensitive ? query : query.toLowerCase()
    );
    const results = [];
    for (const path of this.listFiles(options.pattern)) {
      const haystack = options.caseSensitive ? path : path.toLowerCase();
      let position = 0;
      for (const character of haystack)
        if (character === needle[position]) position++;
      if (position === needle.length)
        results.push({
          path,
          fileName: path,
          matches: [],
          score: needle.length / Array.from(haystack).length
        });
    }
    return results.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path)).slice(0, limit);
  }
  /** Preloads only the paths explicitly requested, subject to normal LRU eviction. */
  preload(paths) {
    this.assertOpen();
    for (const path of paths) this.readEntry(this.fileEntry(path), false);
  }
  /** A background failure closes the archive and is also rethrown by the next data operation. */
  getPreloadError() {
    return this.preloadFailure;
  }
  clearCache() {
    this.cancelAdaptivePreload(true);
    this.cache.clear();
    this.cacheBytes = 0;
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.reconstructor?.clearCache();
    this.source?.cache?.clear();
  }
  getCacheStats() {
    const files = {
      entries: this.cache.size,
      bytes: this.cacheBytes,
      hits: this.cacheHits,
      misses: this.cacheMisses,
      maxBytes: this.fileCacheLimit()
    };
    const blocks = this.reconstructor?.getCacheStats() ?? {
      entries: 0,
      bytes: 0,
      hits: 0,
      misses: 0,
      maxBytes: this.blockCacheLimit()
    };
    const source = this.source?.cache?.getStats() ?? {
      entries: 0,
      bytes: 0,
      hits: 0,
      misses: 0,
      maxBytes: this.sourceCacheLimit()
    };
    return {
      entries: files.entries + blocks.entries + source.entries,
      bytes: files.bytes + blocks.bytes + source.bytes,
      hits: files.hits + blocks.hits + source.hits,
      misses: files.misses + blocks.misses + source.misses,
      maxBytes: this.maxCacheBytes,
      strategy: this.strategy,
      files,
      blocks,
      source
    };
  }
  setCacheStrategy(strategy) {
    this.assertOpen();
    this.validateStrategy(strategy);
    this.strategy = strategy;
    this.clearCache();
    this.reconstructor.setCacheLimit(this.blockCacheLimit());
    this.source?.cache?.setLimit(this.sourceCacheLimit());
  }
  assertOpen() {
    if (this.preloadFailure) throw this.preloadFailure;
    if (!this.source) throw new Error("CHM archive is closed");
    try {
      this.source.validate?.();
    } catch (error) {
      this.close();
      throw error;
    }
  }
  fileEntry(path) {
    this.assertOpen();
    const normalized = normalizePath(path);
    const entry = this.paths.get(normalized.toLowerCase());
    if (!entry) throw new Error(`CHM file not found: ${path}`);
    if (entry.name.endsWith("/"))
      throw new Error(`CHM path is a directory: ${path}`);
    return entry;
  }
  entrySize(entry) {
    return entry.uncompressedLength ?? entry.length;
  }
  checkOutputSize(size) {
    if (size > this.maxFileSize)
      throw new RangeError(
        `Requested output (${size} bytes) exceeds maxFileSize (${this.maxFileSize} bytes); use readRange or createReadStream`
      );
  }
  reconstruct(entry, start, end) {
    if (start === end) return import_buffer.Buffer.alloc(0);
    const data = this.reconstructor.reconstructRange(
      entry.name,
      this.source,
      start,
      end
    );
    if (data.length !== end - start)
      throw new Error(`Incomplete CHM range reconstruction: ${entry.name}`);
    return data;
  }
  cancelAdaptivePreload(reset) {
    if (this.preloadTimer !== void 0) clearTimeout(this.preloadTimer);
    this.preloadTimer = void 0;
    this.preloadQueue = [];
    if (reset) {
      this.preloadPrevious = -1;
      this.preloadTransitions = 0;
    }
  }
  observePreloadAccess(entry) {
    if (!this.adaptivePreload || this.strategy === CacheStrategy.None) return;
    const index = this.preloadIndices.get(entry.name);
    if (index === void 0) return;
    this.cancelAdaptivePreload(false);
    this.preloadTransitions = index === this.preloadPrevious + 1 && this.preloadPrevious >= 0 ? this.preloadTransitions + 1 : 0;
    this.preloadPrevious = index;
    if (this.preloadTransitions < 2) return;
    let remaining = Math.min(
      this.adaptivePreload.maxBytes,
      this.fileCacheLimit() - this.cacheBytes
    );
    const end = Math.min(
      this.preloadOrder.length,
      index + 1 + this.adaptivePreload.maxFiles
    );
    for (let next = index + 1; next < end; next++) {
      const candidate = this.preloadOrder[next];
      if (this.cache.has(candidate.name)) continue;
      const size = this.entrySize(candidate);
      if (size === 0 || size > this.maxFileSize) continue;
      const cost = this.preloadCost(candidate);
      if (cost > remaining) continue;
      remaining -= cost;
      this.preloadQueue.push(candidate);
    }
    if (this.preloadQueue.length)
      this.preloadTimer = setTimeout(() => this.runAdaptivePreload(), 0);
  }
  /** Conservative decode/input span: a tiny compressed file may need a large prefix. */
  preloadCost(entry) {
    const size = this.entrySize(entry);
    if (entry.section === 0) return size;
    if (entry.section !== 1 || size === 0) return Infinity;
    const table = this.parsed.resetTable;
    const reset = this.parsed.header.lzxc.resetInterval;
    const frame = table.blockSize;
    if (!reset || !frame) return Infinity;
    const start = Math.floor(entry.offset / reset) * reset;
    const end = entry.offset + size;
    const lastGroup = Math.floor((end - 1) / reset) * reset;
    const groupSize = Math.min(reset, table.uncompressedLength - lastGroup);
    const decodedEnd = groupSize <= this.blockCacheLimit() ? lastGroup + groupSize : Math.min(table.uncompressedLength, Math.ceil(end / frame) * frame);
    const first = table.entries[start / frame]?.compressedLength;
    const last = table.entries[Math.ceil(decodedEnd / frame)]?.compressedLength ?? table.compressedLength;
    if (first === void 0 || last < first) return Infinity;
    return Math.max(size, decodedEnd - start, last - first);
  }
  runAdaptivePreload() {
    this.preloadTimer = void 0;
    const entry = this.preloadQueue.shift();
    if (!entry) return;
    try {
      this.assertOpen();
      if (this.strategy === CacheStrategy.LRU && !this.cache.has(entry.name) && this.entrySize(entry) <= this.fileCacheLimit() - this.cacheBytes)
        this.readEntry(entry, false);
      if (this.preloadQueue.length)
        this.preloadTimer = setTimeout(() => this.runAdaptivePreload(), 0);
    } catch (error) {
      let message = error instanceof Error ? error.message : String(error);
      try {
        this.close();
      } catch (closeError) {
        message += `; close failed: ${String(closeError)}`;
      }
      this.preloadFailure = new Error(
        `Adaptive preload failed for ${JSON.stringify(entry.name)}: ${message}`
      );
    }
  }
  cachedFile(key) {
    const data = this.cache.get(key);
    if (data) {
      this.cache.delete(key);
      this.cache.set(key, data);
      this.cacheHits++;
    }
    return data;
  }
  evictOldest() {
    const key = this.cache.keys().next().value;
    this.cacheBytes -= this.cache.get(key).length;
    this.cache.delete(key);
  }
  // Charge every retained layer. Pure section-0 archives need no LZX budget;
  // compressed archives favor reusable reset groups over duplicate file bytes.
  sourceCacheLimit() {
    return this.strategy === CacheStrategy.None || !this.source?.cache ? 0 : Math.min(256 * 1024, Math.floor(this.maxCacheBytes / 8));
  }
  fileCacheLimit() {
    if (this.strategy === CacheStrategy.None) return 0;
    const available = this.maxCacheBytes - this.sourceCacheLimit();
    if (!this.parsed?.header.lzxc.signature) return available;
    const resetSize = Math.min(
      this.parsed.header.lzxc.resetInterval,
      this.parsed.resetTable.uncompressedLength
    );
    const blocks = Math.max(
      Math.ceil(available / 2),
      resetSize <= available ? resetSize : 0
    );
    return available - blocks;
  }
  blockCacheLimit() {
    return this.strategy === CacheStrategy.None || !this.parsed?.header.lzxc.signature ? 0 : this.maxCacheBytes - this.sourceCacheLimit() - this.fileCacheLimit();
  }
  validateStrategy(strategy) {
    if (strategy !== CacheStrategy.None && strategy !== CacheStrategy.LRU)
      throw new Error(`Unsupported cache strategy: ${strategy}`);
  }
  decode(path, data, encoding) {
    try {
      return decodeText(
        data,
        encoding ?? this.defaultEncoding,
        languageEncoding(this.parsed.header.itsf.languageId)
      );
    } catch (error) {
      throw new Error(
        `Cannot decode CHM file "${path}" (${encoding ?? this.defaultEncoding ?? "auto"}): ${error instanceof Error ? error.message : String(error)}`,
        { cause: error }
      );
    }
  }
  readNavigation(field, extension) {
    const name = this.getMetadata()[field];
    const canonical = name ? this.resolveLink(name, "/") : void 0;
    const path = canonical && this.exists(canonical) ? canonical : this.listFiles().find((file) => extension.test(file));
    if (!path) return [];
    return parseSitemap(
      this.readHTML(path),
      (local) => this.resolveLink(local, path, true)
    );
  }
  resolveLink(local, from, rootFallback = false) {
    if (/^(?:[a-z][\w+.-]*:|\/\/)/i.test(local)) return local;
    const suffixStart = local.search(/[?#]/);
    const suffix = suffixStart < 0 ? "" : local.slice(suffixStart);
    let path = suffixStart < 0 ? local : local.slice(0, suffixStart);
    try {
      path = decodeURIComponent(path);
    } catch {
    }
    const base = from.slice(0, from.lastIndexOf("/") + 1);
    const resolved = normalizePath(
      path ? /^[\\/]/.test(path) ? path : base + path : from
    );
    let canonical = this.paths.get(resolved.toLowerCase())?.name;
    if (!canonical && rootFallback && path && !/^[.\\/]/.test(path)) {
      canonical = this.paths.get(normalizePath(path).toLowerCase())?.name;
    }
    return (canonical ?? resolved) + suffix;
  }
};

// src/encoder/archive-builder.ts
init_browser_buffer();

// src/encoder/navigation.ts
init_browser_buffer();
function escapeHtml(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function topicURL(path) {
  return path.split("/").map(encodeURIComponent).join("/");
}
function inferTOC(files, folders = false) {
  const root = [];
  const groups = /* @__PURE__ */ new Map();
  groups.set("", root);
  for (const [path, data] of files) {
    if (!/\.html?$/i.test(path)) continue;
    const parts = path.slice(1).split("/");
    if (folders && parts.length > 128)
      throw new Error("Navigation hierarchy exceeds 128 levels");
    const filename = parts.pop();
    let prefix = "";
    let children = root;
    for (const directory of folders ? parts : []) {
      prefix += `/${directory}`;
      let group = groups.get(prefix);
      if (!group) {
        group = [];
        children.push({ name: directory, children: group });
        groups.set(prefix, group);
      }
      children = group;
    }
    const title = data.toString("utf8").match(/<title[^>]*>([^<]*)<\/title>/i)?.[1];
    children.push({
      name: title || (folders ? filename : path.slice(1)),
      local: topicURL(path.slice(1))
    });
  }
  return root;
}
function renderSitemap(entries, validateLocal, template = '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">\n<HTML><HEAD><meta charset="utf-8"></HEAD><BODY><UL>\n{{entries}}\n</UL></BODY></HTML>') {
  if (template.split("{{entries}}").length !== 2)
    throw new Error("tocTemplate must contain exactly one {{entries}}");
  const ancestors = /* @__PURE__ */ new Set();
  let count = 0;
  const render = (items, depth) => {
    if (depth > 128) throw new Error("Navigation hierarchy exceeds 128 levels");
    return items.map((entry) => {
      if (++count > 1e4)
        throw new Error("Navigation exceeds 10000 entries");
      if (ancestors.has(entry))
        throw new Error("Cyclic navigation hierarchy");
      if (typeof entry.name !== "string")
        throw new Error("Invalid navigation name");
      ancestors.add(entry);
      let local = "";
      if (entry.local !== void 0) {
        validateLocal(entry.local);
        local = `<param name="Local" value="${escapeHtml(entry.local.replace(/^\/+/, ""))}">`;
      }
      const children = entry.children?.length ? `<UL>
${render(entry.children, depth + 1)}
</UL>` : "";
      ancestors.delete(entry);
      return `<LI><OBJECT type="text/sitemap"><param name="Name" value="${escapeHtml(entry.name)}">${local}</OBJECT>${children}</LI>`;
    }).join("\n");
  };
  return import_buffer.Buffer.from(
    template.replace("{{entries}}", () => render(entries, 0)),
    "utf8"
  );
}

// src/encoder/builders/header-builder.ts
init_browser_buffer();
var HEADER_GUIDS = import_buffer.Buffer.from(
  "10fd017caa7bd0119e0c00a0c922e6ec11fd017caa7bd0119e0c00a0c922e6ec",
  "hex"
);
var DIRECTORY_GUID = import_buffer.Buffer.from("6a92025d2e21d0119df900a0c922e6ec", "hex");
function encodeEncInt(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Invalid CHM ENCINT: ${value}`);
  }
  const bytes = [value % 128];
  for (value = Math.floor(value / 128); value > 0; value = Math.floor(value / 128)) {
    bytes.unshift(value % 128 | 128);
  }
  return import_buffer.Buffer.from(bytes);
}
var CHMHeaderBuilder = class {
  static createITSFHeader(options) {
    return {
      signature: "ITSF",
      version: 3,
      headerLength: 96,
      unknown1: 1,
      timestamp: options.timestamp ?? Math.floor(Date.now() / 1e3),
      languageId: options.languageId ?? 1033,
      unknown2: options.section0HeaderOffset ?? 96,
      unknown3: options.section0HeaderLength ?? 24,
      directoryOffset: options.directoryOffset,
      directoryLength: options.directoryLength,
      unknown4: options.contentOffset ?? options.directoryOffset + options.directoryLength,
      section0HeaderOffset: options.section0HeaderOffset ?? 96,
      section0HeaderLength: options.section0HeaderLength ?? 24,
      contentOffset: options.contentOffset ?? options.directoryOffset + options.directoryLength
    };
  }
  static createITSPHeader(options = {}) {
    return {
      signature: "ITSP",
      version: 1,
      headerLength: 84,
      unknown1: 10,
      chunkSize: options.chunkSize ?? 4096,
      density: options.density ?? 2,
      depth: options.depth ?? 1,
      rootIndex: -1,
      firstPMGI: 0,
      lastPMGI: (options.numChunks ?? 1) - 1,
      unknown2: -1,
      numChunks: options.numChunks ?? 1,
      languageId: options.languageId ?? 1033
    };
  }
  static createLZXCHeader(options = {}) {
    return {
      signature: "LZXC",
      version: 2,
      resetInterval: options.resetInterval ?? 32768,
      windowSize: options.windowSize ?? 32768,
      cacheSize: options.cacheSize ?? 1,
      unknown: 0
    };
  }
  static serializeITSFHeader(header) {
    const buffer = import_buffer.Buffer.alloc(96);
    buffer.write("ITSF", 0, "ascii");
    buffer.writeUInt32LE(header.version, 4);
    buffer.writeUInt32LE(header.headerLength, 8);
    buffer.writeUInt32LE(header.unknown1, 12);
    buffer.writeUInt32BE(header.timestamp >>> 0, 16);
    buffer.writeUInt32LE(header.languageId, 20);
    HEADER_GUIDS.copy(buffer, 24);
    buffer.writeBigUInt64LE(
      BigInt(header.section0HeaderOffset ?? header.unknown2),
      56
    );
    buffer.writeBigUInt64LE(
      BigInt(header.section0HeaderLength ?? header.unknown3),
      64
    );
    buffer.writeBigUInt64LE(BigInt(header.directoryOffset), 72);
    buffer.writeBigUInt64LE(BigInt(header.directoryLength), 80);
    buffer.writeBigUInt64LE(
      BigInt(header.contentOffset ?? header.unknown4),
      88
    );
    return buffer;
  }
  static serializeITSPHeader(header) {
    const buffer = import_buffer.Buffer.alloc(84);
    buffer.write("ITSP", 0, "ascii");
    buffer.writeUInt32LE(header.version, 4);
    buffer.writeUInt32LE(header.headerLength, 8);
    buffer.writeUInt32LE(header.unknown1, 12);
    buffer.writeUInt32LE(header.chunkSize, 16);
    buffer.writeUInt32LE(header.density, 20);
    buffer.writeUInt32LE(header.depth, 24);
    buffer.writeUInt32LE(header.rootIndex >>> 0, 28);
    buffer.writeUInt32LE(header.firstPMGI >>> 0, 32);
    buffer.writeUInt32LE(header.lastPMGI >>> 0, 36);
    buffer.writeUInt32LE(header.unknown2 >>> 0, 40);
    buffer.writeUInt32LE(header.numChunks ?? header.lastPMGI + 1, 44);
    buffer.writeUInt32LE(header.languageId ?? 1033, 48);
    DIRECTORY_GUID.copy(buffer, 52);
    buffer.writeUInt32LE(84, 68);
    buffer.fill(255, 72);
    return buffer;
  }
  /** ControlData contains its DWORD count before LZXC; v2 sizes are in frames. */
  static serializeLZXCHeader(header) {
    if (header.resetInterval % 32768 || header.windowSize % 32768) {
      throw new Error("LZXC sizes must be multiples of 32 KiB");
    }
    const buffer = import_buffer.Buffer.alloc(28);
    buffer.writeUInt32LE(6, 0);
    buffer.write("LZXC", 4, "ascii");
    buffer.writeUInt32LE(header.version, 8);
    const unit = header.version === 2 ? 32768 : 1;
    buffer.writeUInt32LE(header.resetInterval / unit, 12);
    buffer.writeUInt32LE(header.windowSize / unit, 16);
    buffer.writeUInt32LE(header.cacheSize, 20);
    buffer.writeUInt32LE(header.unknown, 24);
    return buffer;
  }
  /** PMGL leaf chain. A missing PMGI root (-1) permits standard linear lookup. */
  static serializeDirectory(entries, chunkSize = 4096, density = 2) {
    if (chunkSize < 32 || chunkSize > 65536 || !Number.isInteger(chunkSize)) {
      throw new Error("Invalid CHM directory chunk size");
    }
    if (!Number.isInteger(density) || density < 0 || density > 10) {
      throw new Error("Invalid CHM quickref density");
    }
    const stride = 2 ** density + 1;
    const sorted = [...entries].sort((a, b) => {
      const lower = import_buffer.Buffer.compare(
        import_buffer.Buffer.from(a.name.toLowerCase()),
        import_buffer.Buffer.from(b.name.toLowerCase())
      );
      return lower || import_buffer.Buffer.compare(import_buffer.Buffer.from(a.name), import_buffer.Buffer.from(b.name));
    });
    const groups = [];
    let group = [];
    let used = 20;
    for (const entry of sorted) {
      const name = import_buffer.Buffer.from(entry.name, "utf8");
      const encoded = import_buffer.Buffer.concat([
        encodeEncInt(name.length),
        name,
        encodeEncInt(entry.section),
        encodeEncInt(entry.offset),
        encodeEncInt(entry.length)
      ]);
      if (encoded.length + 22 > chunkSize) {
        throw new Error(
          `CHM directory entry exceeds chunk size: ${entry.name}`
        );
      }
      const quickrefSize = 2 * Math.ceil((group.length + 1) / stride);
      if (used + encoded.length + quickrefSize > chunkSize && group.length) {
        groups.push(group);
        group = [];
        used = 20;
      }
      group.push(encoded);
      used += encoded.length;
    }
    if (group.length || !groups.length) groups.push(group);
    return import_buffer.Buffer.concat(
      groups.map((items, index) => {
        const chunk = import_buffer.Buffer.alloc(chunkSize);
        chunk.write("PMGL", 0, "ascii");
        chunk.writeInt32LE(index === 0 ? -1 : index - 1, 12);
        chunk.writeInt32LE(index === groups.length - 1 ? -1 : index + 1, 16);
        let position = 20;
        items.forEach((item, entryIndex) => {
          if (entryIndex > 0 && entryIndex % stride === 0) {
            chunk.writeUInt16LE(
              position - 20,
              chunkSize - 2 - 2 * (entryIndex / stride)
            );
          }
          item.copy(chunk, position);
          position += item.length;
        });
        chunk.writeUInt32LE(chunkSize - position, 4);
        chunk.writeUInt16LE(items.length, chunkSize - 2);
        return chunk;
      })
    );
  }
  /** @deprecated Components are addressable streams, not a contiguous header. */
  static calculateHeaderSize(resetTableSize) {
    return 96 + 24 + 84 + 28 + resetTableSize;
  }
  static validateHeader(header) {
    if (header.signature === "ITSF" && "directoryOffset" in header) {
      return header.version === 3 && header.headerLength === 96 && Number.isSafeInteger(header.directoryOffset) && header.directoryOffset >= 120 && Number.isSafeInteger(header.directoryLength) && header.directoryLength >= 84;
    }
    if (header.signature === "ITSP" && "chunkSize" in header) {
      return header.version === 1 && header.headerLength === 84 && header.chunkSize >= 32 && header.density >= 0 && header.depth >= 1;
    }
    if (header.signature === "LZXC" && "windowSize" in header) {
      return (header.version === 1 || header.version === 2) && header.resetInterval > 0 && header.resetInterval % 32768 === 0 && header.windowSize >= 32768 && header.windowSize <= 2097152 && (header.windowSize & header.windowSize - 1) === 0;
    }
    return false;
  }
};

// src/encoder/lzx-encoder.ts
init_browser_buffer();

// src/encoder/canonical-huffman.ts
init_browser_buffer();
var CanonicalHuffman = class _CanonicalHuffman {
  constructor(lengths) {
    this.lengths = new Uint8Array(lengths);
    this.codes = new Uint16Array(lengths.length);
    const counts = new Uint32Array(17);
    for (const length of lengths) {
      if (length > 16) throw new Error("Huffman length exceeds 16 bits");
      if (length) counts[length]++;
    }
    let free = 1;
    const next = new Uint32Array(17);
    for (let bits = 1; bits <= 16; bits++) {
      free = free * 2 - counts[bits];
      next[bits] = (next[bits - 1] + counts[bits - 1]) * 2;
      if (free < 0) throw new Error("Oversubscribed Huffman tree");
    }
    if (free !== 0) throw new Error("Incomplete Huffman tree");
    for (let symbol = 0; symbol < lengths.length; symbol++) {
      const bits = lengths[symbol];
      if (bits) this.codes[symbol] = next[bits]++;
    }
  }
  static fixed(count) {
    if (!Number.isSafeInteger(count) || count < 2 || count > 65536)
      throw new Error("Huffman alphabet must contain 2..65536 symbols");
    const bits = Math.floor(Math.log2(count));
    const shortCount = 2 ** (bits + 1) - count;
    const lengths = new Uint8Array(count).fill(bits + 1);
    lengths.fill(bits, 0, shortCount);
    return new _CanonicalHuffman(lengths);
  }
  static fromFrequencies(frequencies, maxBits = 16) {
    if (!Number.isInteger(maxBits) || maxBits < 1 || maxBits > 16)
      throw new Error("Invalid Huffman length limit");
    if (frequencies.length < 2 || frequencies.length > 65536)
      throw new Error("Huffman alphabet must contain 2..65536 symbols");
    const leaves = [];
    let total = 0;
    for (let symbol = 0; symbol < frequencies.length; symbol++) {
      const weight = frequencies[symbol];
      total += weight;
      if (!Number.isSafeInteger(weight) || weight < 0 || !Number.isSafeInteger(total))
        throw new Error(
          "Invalid Huffman frequency: counts and their sum must be non-negative safe integers"
        );
      if (weight) leaves.push({ weight, order: symbol, symbol });
    }
    for (let symbol = 0; leaves.length < 2; symbol++) {
      if (!frequencies[symbol])
        leaves.push({ weight: 0, order: symbol, symbol });
    }
    if (leaves.length > 2 ** maxBits)
      throw new Error("Too many symbols for Huffman length limit");
    const compare = (a, b) => a.weight - b.weight || a.order - b.order;
    leaves.sort(compare);
    let list = leaves;
    let order = frequencies.length;
    for (let depth = 1; depth < maxBits; depth++) {
      const packages = [];
      for (let index = 0; index + 1 < list.length; index += 2) {
        const left = list[index];
        const right = list[index + 1];
        packages.push({
          weight: left.weight + right.weight,
          order: order++,
          children: [left, right]
        });
      }
      list = [...leaves, ...packages].sort(compare);
    }
    const lengths = new Uint8Array(frequencies.length);
    const pending = list.slice(0, leaves.length * 2 - 2);
    while (pending.length) {
      const item = pending.pop();
      if (item.children) pending.push(...item.children);
      else lengths[item.symbol]++;
    }
    return new _CanonicalHuffman(lengths);
  }
  write(writer, symbol) {
    const bits = this.lengths[symbol];
    if (!bits) throw new Error(`Missing Huffman symbol: ${symbol}`);
    writer.write(this.codes[symbol], bits);
  }
};

// src/encoder/lzx-encoder.ts
var LZX_FRAME_SIZE = 32768;
var WordWriter = class _WordWriter {
  constructor() {
    this.bytes = [];
    this.word = 0;
    this.used = 0;
  }
  write(value, bits) {
    while (bits > 0) {
      const take = Math.min(16 - this.used, bits);
      bits -= take;
      this.word = this.word << take | value >>> bits & 2 ** take - 1;
      this.used += take;
      if (this.used === 16) {
        this.bytes.push(this.word & 255, this.word >>> 8);
        this.word = this.used = 0;
      }
    }
  }
  get bitLength() {
    return this.bytes.length * 8 + this.used;
  }
  clone() {
    const copy = new _WordWriter();
    copy.bytes.push(...this.bytes);
    copy.word = this.word;
    copy.used = this.used;
    return copy;
  }
  raw(data) {
    this.write(0, 16 - this.used);
    for (const byte of data) this.bytes.push(byte);
  }
  finish() {
    if (this.used) this.write(0, 16 - this.used);
    return import_buffer.Buffer.from(this.bytes);
  }
};
var LENGTH_TREE = CanonicalHuffman.fixed(249);
var MatchFinder = class {
  constructor(data, windowSize, searchDepth, paddedLength) {
    this.data = data;
    this.windowSize = windowSize;
    this.searchDepth = searchDepth;
    this.paddedLength = paddedLength;
    this.heads = new Float64Array(65536).fill(-1);
    this.resetStart = 0;
    this.previous = new Float64Array(windowSize);
  }
  reset(position) {
    this.heads.fill(-1);
    this.resetStart = position;
  }
  byte(position) {
    return this.data[position] ?? 0;
  }
  hash(position) {
    const value = this.byte(position) << 16 | this.byte(position + 1) << 8 | this.byte(position + 2);
    return Math.imul(value, 506832829) >>> 16 & 65535;
  }
  insert(position) {
    if (position + 2 >= this.paddedLength) return;
    const hash = this.hash(position);
    this.previous[position % this.windowSize] = this.heads[hash];
    this.heads[hash] = position;
  }
  tokenize(start, end) {
    const tokens = [];
    let position = start;
    while (position < end) {
      let bestLength = 0;
      let bestDistance = 0;
      const maximum = Math.min(257, end - position);
      if (maximum >= 3) {
        let candidate = this.heads[this.hash(position)];
        const minimum = Math.max(
          this.resetStart,
          position - this.windowSize + 3
        );
        for (let searched = 0; candidate >= minimum && searched < this.searchDepth; searched++) {
          if (this.byte(candidate + bestLength) === this.byte(position + bestLength)) {
            let length = 0;
            while (length < maximum && this.byte(candidate + length) === this.byte(position + length))
              length++;
            if (length > bestLength) {
              bestLength = length;
              bestDistance = position - candidate;
              if (length === maximum) break;
            }
          }
          const next = this.previous[candidate % this.windowSize];
          if (next >= candidate) break;
          candidate = next;
        }
      }
      if (bestLength >= 3) {
        tokens.push({ length: bestLength, distance: bestDistance });
        for (let index = 0; index < bestLength; index++)
          this.insert(position + index);
        position += bestLength;
      } else {
        tokens.push(this.byte(position));
        this.insert(position++);
      }
    }
    return tokens;
  }
};
var LZXEncoder = class {
  constructor(config = {}) {
    this.positionBases = [];
    this.extraBits = [];
    for (const key of [
      "windowSize",
      "resetInterval",
      "compressionLevel",
      "blockSize"
    ]) {
      if (config[key] !== void 0 && typeof config[key] !== "number")
        throw new Error(`LZX ${key} must be a number`);
    }
    this.windowSize = config.windowSize ?? LZX_FRAME_SIZE;
    this.resetInterval = config.resetInterval ?? LZX_FRAME_SIZE;
    this.compressionLevel = config.compressionLevel ?? 6;
    this.blockSize = config.blockSize ?? LZX_FRAME_SIZE;
    if (!Number.isInteger(this.blockSize) || this.blockSize < 256 || this.blockSize > LZX_FRAME_SIZE || (this.blockSize & this.blockSize - 1) !== 0)
      throw new Error("LZX blockSize must be a power of two from 256 to 32768");
    if (!Number.isInteger(this.windowSize) || this.windowSize < LZX_FRAME_SIZE || this.windowSize > 2097152 || (this.windowSize & this.windowSize - 1) !== 0) {
      throw new Error(
        "LZX windowSize must be a power of two from 32 KiB to 2 MiB"
      );
    }
    if (!Number.isSafeInteger(this.resetInterval) || this.resetInterval <= 0 || this.resetInterval % LZX_FRAME_SIZE !== 0) {
      throw new Error(
        "LZX resetInterval must be a positive multiple of 32 KiB"
      );
    }
    if (!Number.isInteger(this.compressionLevel) || this.compressionLevel < 0 || this.compressionLevel > 9) {
      throw new Error("LZX compressionLevel must be an integer from 0 to 9");
    }
    const slots = [30, 32, 34, 36, 38, 42, 50][Math.log2(this.windowSize) - 15];
    this.mainTree = CanonicalHuffman.fixed(256 + slots * 8);
    let base = 0;
    for (let slot = 0; slot < slots; slot++) {
      const extra = slot < 4 ? 0 : Math.min(17, Math.floor(slot / 2) - 1);
      this.positionBases.push(base);
      this.extraBits.push(extra);
      base += 2 ** extra;
    }
  }
  compress(inputBuffer) {
    const chunks = [];
    const offsets = [];
    let compressedSize = 0;
    const paddedSize = Math.ceil(inputBuffer.length / LZX_FRAME_SIZE) * LZX_FRAME_SIZE;
    const data = inputBuffer;
    const finder = this.compressionLevel === 0 || paddedSize === 0 ? void 0 : new MatchFinder(
      data,
      this.windowSize,
      2 ** this.compressionLevel,
      paddedSize
    );
    const previousMain = new Uint8Array(this.mainTree.lengths.length);
    const previousLength = new Uint8Array(LENGTH_TREE.lengths.length);
    let recent = [1, 1, 1];
    for (let position = 0; position < paddedSize; position += LZX_FRAME_SIZE) {
      offsets.push(compressedSize);
      const length = Math.min(LZX_FRAME_SIZE, inputBuffer.length - position);
      const reset = position % this.resetInterval === 0;
      if (reset) {
        finder?.reset(position);
        previousMain.fill(0);
        previousLength.fill(0);
        recent = [1, 1, 1];
      }
      let writer = new WordWriter();
      if (reset) writer.write(0, 1);
      for (let offset = 0; offset < LZX_FRAME_SIZE; offset += this.blockSize) {
        const start = position + offset;
        const logicalLength = Math.max(
          0,
          Math.min(this.blockSize, length - offset)
        );
        let selected = writer.clone();
        if (logicalLength > 0) {
          this.storedBlock(
            selected,
            data.subarray(start, start + logicalLength),
            recent
          );
        }
        if (logicalLength < this.blockSize) {
          this.storedBlock(
            selected,
            import_buffer.Buffer.alloc(this.blockSize - logicalLength),
            recent
          );
        }
        let selectedMain;
        let selectedLength;
        if (finder) {
          const tokens = finder.tokenize(start, start + this.blockSize);
          const mainFrequencies = new Array(
            this.mainTree.lengths.length
          ).fill(0);
          const lengthFrequencies = new Array(249).fill(0);
          const alignedFrequencies = new Array(8).fill(0);
          for (const token of tokens) {
            if (typeof token === "number") mainFrequencies[token]++;
            else {
              const slot = this.slot(token.distance);
              mainFrequencies[256 + slot * 8 + Math.min(token.length - 2, 7)]++;
              if (token.length >= 9) lengthFrequencies[token.length - 9]++;
              if (this.extraBits[slot] >= 3)
                alignedFrequencies[token.distance - (this.positionBases[slot] - 2) & 7]++;
            }
          }
          const trees = [
            [this.mainTree, LENGTH_TREE]
          ];
          if (this.compressionLevel >= 2)
            trees.push([
              CanonicalHuffman.fromFrequencies(mainFrequencies),
              CanonicalHuffman.fromFrequencies(lengthFrequencies)
            ]);
          const aligned = this.compressionLevel >= 4 ? CanonicalHuffman.fromFrequencies(alignedFrequencies, 7) : void 0;
          for (const [main, secondary] of trees) {
            for (const alignment of aligned ? [void 0, aligned] : [void 0]) {
              const candidate = writer.clone();
              this.compressedBlock(
                candidate,
                tokens,
                main,
                secondary,
                alignment,
                previousMain,
                previousLength
              );
              const last = offset + this.blockSize === LZX_FRAME_SIZE;
              const cost = (bits) => last ? Math.ceil(bits / 16) : bits;
              if (cost(candidate.bitLength) < cost(selected.bitLength)) {
                selected = candidate;
                selectedMain = main;
                selectedLength = secondary;
              }
            }
          }
          if (selectedMain) {
            previousMain.set(selectedMain.lengths);
            previousLength.set(selectedLength.lengths);
            for (const token of tokens) {
              if (typeof token !== "number")
                recent = [token.distance, recent[0], recent[1]];
            }
          }
        }
        writer = selected;
      }
      const frame = writer.finish();
      chunks.push(frame);
      compressedSize += frame.length;
    }
    const resetTable = import_buffer.Buffer.alloc(40 + offsets.length * 8);
    resetTable.writeUInt32LE(2, 0);
    resetTable.writeUInt32LE(offsets.length, 4);
    resetTable.writeUInt32LE(8, 8);
    resetTable.writeUInt32LE(40, 12);
    resetTable.writeBigUInt64LE(BigInt(inputBuffer.length), 16);
    resetTable.writeBigUInt64LE(BigInt(compressedSize), 24);
    resetTable.writeBigUInt64LE(BigInt(LZX_FRAME_SIZE), 32);
    offsets.forEach(
      (offset, index) => resetTable.writeBigUInt64LE(BigInt(offset), 40 + index * 8)
    );
    return {
      compressedData: import_buffer.Buffer.concat(chunks, compressedSize),
      resetTable,
      uncompressedSize: inputBuffer.length,
      compressedSize
    };
  }
  writeTree(writer, previous, lengths, start, end) {
    const operations = [];
    for (let symbol = start; symbol < end; ) {
      let run = 0;
      if (lengths[symbol] === 0) {
        while (symbol + run < end && lengths[symbol + run] === 0 && run < 51)
          run++;
      }
      if (run >= 4) {
        const long = run >= 20;
        operations.push({
          symbol: long ? 18 : 17,
          extra: run - (long ? 20 : 4),
          bits: long ? 5 : 4
        });
        symbol += run;
      } else {
        operations.push({
          symbol: (previous[symbol] - lengths[symbol] + 17) % 17
        });
        symbol++;
      }
    }
    const frequencies = new Array(20).fill(0);
    for (const operation of operations) frequencies[operation.symbol]++;
    const pretree = CanonicalHuffman.fromFrequencies(frequencies, 15);
    for (const length of pretree.lengths) writer.write(length, 4);
    for (const operation of operations) {
      pretree.write(writer, operation.symbol);
      if (operation.bits) writer.write(operation.extra, operation.bits);
    }
  }
  slot(distance) {
    let slot = this.positionBases.length - 1;
    while (slot > 3 && distance < this.positionBases[slot] - 2) slot--;
    return slot;
  }
  compressedBlock(writer, tokens, main, secondary, aligned, previousMain, previousLength) {
    writer.write(aligned ? 2 : 1, 3);
    writer.write(this.blockSize, 24);
    if (aligned) for (const length of aligned.lengths) writer.write(length, 3);
    this.writeTree(writer, previousMain, main.lengths, 0, 256);
    this.writeTree(
      writer,
      previousMain,
      main.lengths,
      256,
      main.lengths.length
    );
    this.writeTree(
      writer,
      previousLength,
      secondary.lengths,
      0,
      secondary.lengths.length
    );
    for (const token of tokens) {
      if (typeof token === "number") {
        main.write(writer, token);
        continue;
      }
      const slot = this.slot(token.distance);
      const lengthCode = token.length - 2;
      main.write(writer, 256 + slot * 8 + Math.min(lengthCode, 7));
      if (lengthCode >= 7) secondary.write(writer, token.length - 9);
      const suffix = token.distance - (this.positionBases[slot] - 2);
      const extra = this.extraBits[slot];
      if (aligned && extra >= 3) {
        writer.write(suffix >>> 3, extra - 3);
        aligned.write(writer, suffix & 7);
      } else writer.write(suffix, extra);
    }
  }
  storedBlock(writer, data, recent) {
    writer.write(3, 3);
    writer.write(data.length, 24);
    const block = import_buffer.Buffer.alloc(12 + data.length + (data.length & 1));
    recent.forEach(
      (distance, index) => block.writeUInt32LE(distance, index * 4)
    );
    block.set(data, 12);
    writer.raw(block);
  }
  getConfig() {
    return {
      windowSize: this.windowSize,
      resetInterval: this.resetInterval,
      compressionLevel: this.compressionLevel,
      ...this.blockSize === LZX_FRAME_SIZE ? {} : { blockSize: this.blockSize }
    };
  }
};

// src/encoder/archive-builder.ts
var STORAGE2 = "::DataSpace/Storage/MSCompressed/";
var TRANSFORM = "{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}";
function normalizeArchivePath(name) {
  if (name.replace(/\\/g, "/").startsWith("//"))
    throw new Error(`Network paths are not allowed in CHM paths: ${name}`);
  const normalized = name.replace(/\\/g, "/").replace(/^\/+/, "").replace(/\/+/g, "/");
  if (!normalized || normalized.includes("\0") || /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u.test(
    normalized
  )) {
    throw new Error(`Invalid CHM path: ${name}`);
  }
  if (normalized.split("/").some((part) => part === "." || part === "..")) {
    throw new Error(
      `Relative path components are not allowed in CHM paths: ${name}`
    );
  }
  if (normalized.startsWith("::") || /^[#$]/.test(normalized)) {
    throw new Error(`Reserved CHM path: ${name}`);
  }
  const components = normalized.replace(/\/$/, "").split("/");
  if (/[:<>"|?*]/.test(normalized) || Array.from(normalized).some((character) => character.charCodeAt(0) < 32) || components.some(
    (part) => /[. ]$/.test(part) || /^(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[0-9¹²³]|lpt[0-9¹²³])$/i.test(
      part.split(".")[0].replace(/[. ]+$/, "")
    )
  ))
    throw new Error(`Non-portable CHM path: ${name}`);
  return `/${normalized}`;
}
var pathKey = (name) => name.normalize("NFC").toLowerCase();
function sitemap(files) {
  const items = [...files].filter(([name]) => /\.html?$/i.test(name)).map(([name, data]) => {
    const title = data.toString("utf8").match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] || name.slice(1);
    return `<LI><OBJECT type="text/sitemap"><param name="Name" value="${escapeHtml(title)}"><param name="Local" value="${escapeHtml(topicURL(name.slice(1)))}"></OBJECT></LI>`;
  });
  return import_buffer.Buffer.from(
    `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML><HEAD><meta charset="utf-8"></HEAD><BODY><UL>
${items.join("\n")}
</UL></BODY></HTML>`,
    "utf8"
  );
}
function nameList(compression) {
  const names = compression ? ["Uncompressed", "MSCompressed"] : ["Uncompressed"];
  const parts = names.map((name) => {
    const data = import_buffer.Buffer.from(`${name}\0`, "utf16le");
    const length = import_buffer.Buffer.alloc(2);
    length.writeUInt16LE(name.length);
    return import_buffer.Buffer.concat([length, data]);
  });
  const buffer = import_buffer.Buffer.concat([import_buffer.Buffer.alloc(4), ...parts]);
  buffer.writeUInt16LE(buffer.length / 2, 0);
  buffer.writeUInt16LE(names.length, 2);
  return buffer;
}
function systemMetadata(title, defaultTopic, contents, index, languageId, metadata = {}) {
  const version = import_buffer.Buffer.alloc(4);
  version.writeUInt32LE(3);
  const records = [
    [0, contents],
    [1, index],
    [2, defaultTopic],
    [3, title],
    [9, metadata.compiler ?? "chmkit"]
  ];
  if (metadata.defaultWindow !== void 0)
    records.push([5, metadata.defaultWindow]);
  if (metadata.compiledFile !== void 0)
    records.push([6, metadata.compiledFile]);
  if (metadata.defaultFont !== void 0)
    records.push([16, metadata.defaultFont]);
  const parts = [version];
  for (const [code, text] of records) {
    if (text.includes("\0"))
      throw new Error("CHM metadata cannot contain NUL characters");
    const data = import_buffer.Buffer.from(`${text}\0`, "utf8");
    if (data.length > 65535)
      throw new Error("CHM metadata value exceeds 65535 bytes");
    const header = import_buffer.Buffer.alloc(4);
    header.writeUInt16LE(code, 0);
    header.writeUInt16LE(data.length, 2);
    parts.push(header, data);
  }
  const properties = import_buffer.Buffer.alloc(40);
  properties.writeUInt16LE(4, 0);
  properties.writeUInt16LE(36, 2);
  properties.writeUInt32LE(languageId, 4);
  parts.push(properties);
  for (const [code, bytes] of metadata.extraRecords ?? []) {
    if (!Number.isInteger(code) || code < 0 || code > 65535 || [0, 1, 2, 3, 4, 5, 6, 9, 16].includes(code))
      throw new Error(`Reserved or invalid HTML Help metadata code: ${code}`);
    if (bytes.length > 65535)
      throw new Error("CHM metadata value exceeds 65535 bytes");
    const header = import_buffer.Buffer.alloc(4);
    header.writeUInt16LE(code, 0);
    header.writeUInt16LE(bytes.length, 2);
    parts.push(header, import_buffer.Buffer.from(bytes));
  }
  return import_buffer.Buffer.concat(parts);
}
function prepareFiles(files, copyBytes = true) {
  const input = /* @__PURE__ */ new Map();
  const names = /* @__PURE__ */ new Set();
  for (const [name, data] of files) {
    const normalized = normalizeArchivePath(name);
    if (names.has(pathKey(normalized))) {
      throw new Error(`Duplicate CHM path (case-insensitive): ${name}`);
    }
    if (normalized.endsWith("/") && data.length)
      throw new Error(`Directory has content: ${name}`);
    names.add(pathKey(normalized));
    input.set(
      normalized,
      !copyBytes && import_buffer.Buffer.isBuffer(data) ? data : import_buffer.Buffer.from(data)
    );
  }
  for (const name of input.keys()) {
    const components = name.slice(1).split("/");
    components.pop();
    let parent = "";
    for (const component of components) {
      parent += `/${component}`;
      if (names.has(pathKey(parent)))
        throw new Error(`File is also a parent directory: ${parent}`);
      if (!names.has(pathKey(`${parent}/`))) {
        names.add(pathKey(`${parent}/`));
        input.set(`${parent}/`, import_buffer.Buffer.alloc(0));
      }
    }
    if (name.endsWith("/") && names.has(pathKey(name.slice(0, -1)))) {
      throw new Error(`File/directory path conflict: ${name}`);
    }
  }
  return input;
}
function mergeFileChanges(files, changes, maxBytes = Infinity) {
  const planned = new Map(files);
  const replacements = [];
  const keys = new Map([...files.keys()].map((name) => [pathKey(name), name]));
  const changed = /* @__PURE__ */ new Set();
  const deletedDirectories = [];
  for (const [name, bytes] of changes) {
    const normalized = normalizeArchivePath(name);
    const key = pathKey(normalized);
    if (changed.has(key)) throw new Error(`Ambiguous update path: ${name}`);
    changed.add(key);
    const original = keys.get(key);
    if (bytes === null) {
      if (!original) throw new Error(`Cannot delete missing CHM path: ${name}`);
      if (original.endsWith("/")) deletedDirectories.push(original);
      planned.delete(original);
    } else {
      const target = original ?? normalized;
      planned.set(target, bytes);
      replacements.push(target);
    }
  }
  for (const directory of deletedDirectories) {
    if ([...planned.keys()].some(
      (path) => pathKey(path).startsWith(pathKey(directory))
    ))
      throw new Error(`Cannot delete nonempty directory: ${directory}`);
  }
  let total = 0;
  for (const bytes of planned.values()) {
    total += bytes.length;
    if (!Number.isSafeInteger(total))
      throw new Error("CHM payload size exceeds the safe integer range");
    if (total > maxBytes)
      throw new Error(
        "updateArchive resulting payloads exceed the 256 MiB safety limit"
      );
  }
  for (const name of replacements)
    planned.set(name, import_buffer.Buffer.from(planned.get(name)));
  return prepareFiles(planned, false);
}
function packTemplate(templateFiles, overrides, options = {}) {
  return packPreparedFiles(
    mergeFileChanges(prepareFiles(templateFiles), overrides),
    options
  );
}
function packFiles(files, options = {}) {
  return packPreparedFiles(prepareFiles(files), options);
}
function packPreparedFiles(input, options) {
  const names = new Set([...input.keys()].map(pathKey));
  const references = new Set([...input.keys()].map((name) => name.toLowerCase()));
  function validateLocal(local) {
    validateTopic(local, references);
  }
  function navigationFile(option, extension) {
    if (option === void 0)
      return [...input.keys()].find((name) => extension.test(name));
    const normalized = normalizeArchivePath(option);
    const existing = [...input.keys()].find(
      (name) => pathKey(name) === pathKey(normalized)
    );
    if (!existing || existing.endsWith("/"))
      throw new Error(`Navigation file not found: ${option}`);
    return existing;
  }
  const existingContents = navigationFile(options.contentsFile, /\.hhc$/i);
  const existingIndex = navigationFile(options.indexFile, /\.hhk$/i);
  if (options.tocHierarchy !== void 0 && !["flat", "folders"].includes(options.tocHierarchy))
    throw new Error("tocHierarchy must be flat or folders");
  if (existingContents && (options.tocEntries !== void 0 || options.tocTemplate !== void 0 || options.tocHierarchy !== void 0))
    throw new Error(
      "tocEntries/tocTemplate cannot replace an existing contents file; edit that file explicitly"
    );
  function addNavigation(preferred, navigation) {
    let name = `/${preferred}`;
    let suffix = 1;
    while (names.has(pathKey(name)) || names.has(pathKey(`${name}/`))) {
      name = `/chmkit-${suffix++}-${preferred}`;
    }
    input.set(name, navigation);
    names.add(pathKey(name));
    references.add(name.toLowerCase());
    return name;
  }
  const contents = existingContents ?? addNavigation(
    "Table of Contents.hhc",
    renderSitemap(
      options.tocEntries ?? inferTOC(input, options.tocHierarchy === "folders"),
      validateLocal,
      options.tocTemplate
    )
  );
  const index = existingIndex ?? addNavigation("Index.hhk", sitemap(input));
  const defaultTopic = options.defaultTopic === void 0 ? topicURL(
    ([...input.keys()].find((name) => /^\/index\.html?$/i.test(name)) ?? [...input.keys()].find((name) => /\.html?$/i.test(name)) ?? "").replace(/^\//, "")
  ) : options.defaultTopic.replace(/\\/g, "/").replace(/^\/+/, "");
  if (defaultTopic) validateTopic(defaultTopic, references);
  const languageId = options.languageId ?? 1033;
  if (!Number.isInteger(languageId) || languageId < 0 || languageId > 4294967295)
    throw new Error("languageId must be an unsigned 32-bit LCID");
  return serializeArchive(
    input,
    systemMetadata(
      options.title ?? "CHM Help File",
      defaultTopic,
      contents.slice(1).replace(/[%#]/g, (character) => encodeURIComponent(character)),
      index.slice(1).replace(/[%#]/g, (character) => encodeURIComponent(character)),
      languageId,
      options.htmlHelp
    ),
    options,
    { languageId }
  );
}
function validateTopic(local, names) {
  if (typeof local !== "string" || Array.from(local).some((character) => character.charCodeAt(0) < 32))
    throw new Error("Invalid topic URL");
  let path = local.split(/[?#]/)[0];
  try {
    path = decodeURIComponent(path);
  } catch {
  }
  const normalized = normalizeArchivePath(path);
  if (normalized.endsWith("/") || !names.has(normalized.toLowerCase()))
    throw new Error(
      `Default topic / navigation Local does not name a file in the archive: ${local}`
    );
}
function serializeArchive(input, system, options, header) {
  if (options.compression !== void 0 && typeof options.compression !== "boolean")
    throw new Error("compression must be a boolean");
  for (const key of [
    "windowBits",
    "resetInterval",
    "blockSize",
    "compressionLevel"
  ]) {
    if (options[key] !== void 0 && typeof options[key] !== "number")
      throw new Error(`${key} must be a number`);
  }
  const windowBits = options.windowBits ?? 15;
  if (!Number.isInteger(windowBits) || windowBits < 15 || windowBits > 21)
    throw new Error("windowBits must be an integer from 15 to 21");
  const resetInterval = options.resetInterval ?? LZX_FRAME_SIZE;
  const resetFrames = resetInterval / LZX_FRAME_SIZE;
  if (!Number.isSafeInteger(resetInterval) || !Number.isInteger(Math.log2(resetFrames)) || resetFrames < 1 || resetFrames > 8192)
    throw new Error(
      "CHM resetInterval must be a power-of-two multiple of 32768, at most 256 MiB"
    );
  const encoder = new LZXEncoder({
    windowSize: 2 ** windowBits,
    resetInterval,
    blockSize: options.blockSize,
    compressionLevel: options.compressionLevel
  });
  const compressed = options.compression !== false;
  const entries = [];
  const section0 = [];
  let section0Size = 0;
  function addUncompressed(name, data) {
    entries.push({
      name,
      section: 0,
      isCompressed: false,
      offset: section0Size,
      length: data.length
    });
    section0.push(data);
    section0Size += data.length;
  }
  addUncompressed("/#SYSTEM", system);
  addUncompressed("::DataSpace/NameList", nameList(compressed));
  const stream = [];
  let streamSize = 0;
  for (const [name, data] of input) {
    if (name.endsWith("/")) {
      entries.push({
        name,
        section: 0,
        isCompressed: false,
        offset: 0,
        length: 0
      });
    } else if (compressed && !/^\/[#$]/.test(name)) {
      entries.push({
        name,
        section: 1,
        isCompressed: true,
        offset: streamSize,
        length: data.length,
        uncompressedLength: data.length
      });
      stream.push(data);
      streamSize += data.length;
    } else {
      addUncompressed(name, data);
    }
  }
  if (compressed) {
    const remainder = streamSize % LZX_FRAME_SIZE;
    const endPadding = remainder === 0 ? 1 : remainder === LZX_FRAME_SIZE - 1 ? 2 : 0;
    if (endPadding) {
      stream.push(import_buffer.Buffer.alloc(endPadding));
      streamSize += endPadding;
    }
    const result = encoder.compress(import_buffer.Buffer.concat(stream, streamSize));
    const config = encoder.getConfig();
    addUncompressed(
      `${STORAGE2}ControlData`,
      CHMHeaderBuilder.serializeLZXCHeader(
        CHMHeaderBuilder.createLZXCHeader(config)
      )
    );
    const span = import_buffer.Buffer.alloc(8);
    span.writeBigUInt64LE(BigInt(streamSize));
    addUncompressed(`${STORAGE2}SpanInfo`, span);
    addUncompressed(
      `${STORAGE2}Transform/List`,
      import_buffer.Buffer.from("4089c27f319dd0119b2700a0c91e9c7c", "hex")
    );
    addUncompressed(
      `${STORAGE2}Transform/${TRANSFORM}/InstanceData/ResetTable`,
      result.resetTable
    );
    addUncompressed(`${STORAGE2}Content`, result.compressedData);
  }
  let chunkSize = 4096;
  const longestEntry = entries.reduce(
    (size, entry) => Math.max(size, import_buffer.Buffer.byteLength(entry.name, "utf8") + 50),
    0
  );
  while (chunkSize < longestEntry && chunkSize < 65536) chunkSize *= 2;
  const directory = CHMHeaderBuilder.serializeDirectory(entries, chunkSize);
  const itsp = CHMHeaderBuilder.serializeITSPHeader(
    CHMHeaderBuilder.createITSPHeader({
      chunkSize,
      numChunks: directory.length / chunkSize,
      languageId: header.directoryLanguageId ?? header.languageId
    })
  );
  const directoryOffset = 120;
  const directoryLength = itsp.length + directory.length;
  const itsf = CHMHeaderBuilder.serializeITSFHeader(
    CHMHeaderBuilder.createITSFHeader({
      directoryOffset,
      directoryLength,
      contentOffset: directoryOffset + directoryLength,
      languageId: header.languageId,
      timestamp: header.timestamp
    })
  );
  const auxiliary = import_buffer.Buffer.alloc(24);
  auxiliary.writeUInt32LE(510, 0);
  auxiliary.writeBigUInt64LE(
    BigInt(directoryOffset + directoryLength + section0Size),
    8
  );
  return import_buffer.Buffer.concat([itsf, auxiliary, itsp, directory, ...section0]);
}
function updateArchive(existing, changes, options = {}) {
  const data = import_buffer.Buffer.from(existing);
  const parsed = new CHMParser().parse(new BitReader(data));
  const allowed = /* @__PURE__ */ new Set([
    "compression",
    "compressionLevel",
    "windowBits",
    "resetInterval",
    "blockSize"
  ]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key))
      throw new Error(
        `Unsupported updateArchive option: ${key}; metadata is preserved verbatim`
      );
  }
  const supplied = Object.fromEntries(
    Object.entries(options).filter(([, value]) => value !== void 0)
  );
  if (changes.size === 0 && Object.keys(supplied).length === 0) return data;
  const infrastructure = new Set(
    [
      "::DataSpace/NameList",
      `${STORAGE2}Content`,
      `${STORAGE2}ControlData`,
      `${STORAGE2}SpanInfo`,
      `${STORAGE2}Transform/List`,
      `${STORAGE2}Transform/${TRANSFORM}/InstanceData/ResetTable`
    ].map(pathKey)
  );
  const compressed = parsed.header.lzxc.signature === "LZXC";
  const span = import_buffer.Buffer.alloc(8);
  span.writeBigUInt64LE(BigInt(parsed.resetTable.uncompressedLength));
  const expectedTransport = /* @__PURE__ */ new Map([
    [pathKey("::DataSpace/NameList"), nameList(compressed)],
    [
      pathKey(`${STORAGE2}Transform/List`),
      import_buffer.Buffer.from("4089c27f319dd0119b2700a0c91e9c7c", "hex")
    ],
    [pathKey(`${STORAGE2}SpanInfo`), span]
  ]);
  const reconstructor = new FileReconstructor(parsed);
  const user = /* @__PURE__ */ new Map();
  const opaque = /* @__PURE__ */ new Map();
  const allNames = /* @__PURE__ */ new Set();
  let system;
  let total = 0;
  for (const [name, entry] of parsed.directory.entries) {
    const key = pathKey(name);
    if (allNames.has(key))
      throw new Error(`Ambiguous existing CHM path: ${name}`);
    allNames.add(key);
    if (entry.section !== 0 && entry.section !== 1)
      throw new Error(`Cannot safely update unsupported CHM section: ${name}`);
    if (name.endsWith("/") && entry.length !== 0)
      throw new Error(`Cannot safely update directory with content: ${name}`);
    if (name.startsWith("::")) {
      const expected = expectedTransport.get(key);
      if (expected && (entry.length !== expected.length || !reconstructor.reconstructFile(name, new BitReader(data)).data.equals(expected)))
        throw new Error(
          `Cannot safely update nonstandard CHM transport metadata: ${name}`
        );
      if (key === pathKey(`${STORAGE2}ControlData`) && entry.length > 28)
        throw new Error(
          `Cannot safely update extended LZX ControlData: ${name}`
        );
      if (infrastructure.has(key) || name.endsWith("/") && [...infrastructure].some((path) => path.startsWith(key)))
        continue;
      throw new Error(
        `Cannot safely update unknown CHM DataSpace stream: ${name}`
      );
    }
    if (/^\/(?:\$|#(?:TOPICS|STRINGS|URLTBL|URLSTR|TOCIDX|IDXHDR|FIftiMain|ITBITS|WINDOWS)(?:$|\/))/i.test(
      name
    ))
      throw new Error(
        `Cannot safely update compiled HTML Help indexes/structures: ${name}`
      );
    total += entry.length;
    if (!Number.isSafeInteger(total) || total > 256 * 1024 * 1024)
      throw new Error(
        "updateArchive reconstructed content exceeds 256 MiB safety limit"
      );
    const bytes = entry.length === 0 ? import_buffer.Buffer.alloc(0) : reconstructor.reconstructFile(name, new BitReader(data)).data;
    if (key === "/#system") system = bytes;
    else if (/^\/[#$]/.test(name)) {
      const portable = name.replace(/^\/[#$]/, "/metadata-");
      if (normalizeArchivePath(portable) !== portable)
        throw new Error(
          `Cannot safely preserve nonportable metadata path: ${name}`
        );
      opaque.set(name, bytes);
    } else user.set(name, bytes);
  }
  if (!system || system.length < 4)
    throw new Error("Cannot update archive without valid #SYSTEM metadata");
  prepareFiles(
    new Map(
      [...opaque].map(([name, bytes]) => [
        name.replace(/^\/[#$]/, "/metadata-"),
        bytes
      ])
    ),
    false
  );
  const metadataBytes = system.length + [...opaque.values()].reduce((sum, bytes) => sum + bytes.length, 0);
  const input = mergeFileChanges(
    prepareFiles(user, false),
    changes,
    256 * 1024 * 1024 - metadataBytes
  );
  const names = new Set([...input.keys()].map((name) => name.toLowerCase()));
  for (let offset = 4; offset < system.length; ) {
    if (offset + 4 > system.length) throw new Error("Truncated #SYSTEM record");
    const code = system.readUInt16LE(offset);
    const length = system.readUInt16LE(offset + 2);
    offset += 4;
    if (offset + length > system.length)
      throw new Error("Truncated #SYSTEM value");
    if (code <= 2 && length > 0) {
      const bytes = system.subarray(offset, offset + length);
      let local;
      try {
        local = new TextDecoder("utf-8", { fatal: true }).decode(bytes).replace(/\0[\s\S]*$/, "");
      } catch {
        throw new Error(
          "Cannot safely validate legacy-encoded #SYSTEM navigation references"
        );
      }
      if (local) validateTopic(local, names);
    }
    offset += length;
  }
  for (const [name, bytes] of opaque) input.set(name, bytes);
  return serializeArchive(
    input,
    system,
    {
      compression: compressed,
      ...compressed ? {
        windowBits: Math.log2(parsed.header.lzxc.windowSize),
        resetInterval: parsed.header.lzxc.resetInterval
      } : {},
      ...supplied
    },
    {
      languageId: parsed.header.itsf.languageId,
      directoryLanguageId: data.readUInt32LE(
        parsed.header.itsf.directoryOffset + 48
      ),
      timestamp: parsed.header.itsf.timestamp
    }
  );
}

// src/browser.ts
var CHMReader = class _CHMReader {
  constructor(input, options) {
    if (!(input instanceof Uint8Array) && !(input instanceof ArrayBuffer)) {
      throw new TypeError(
        "CHMReader expects Uint8Array or ArrayBuffer; use open() for Blob sources"
      );
    }
    this.archive = new CHMArchive(input, options);
  }
  static async open(source, options) {
    if (source instanceof Uint8Array || source instanceof ArrayBuffer)
      return new _CHMReader(source, options);
    if (typeof Blob !== "undefined" && source instanceof Blob)
      return new _CHMReader(await source.arrayBuffer(), options);
    throw new TypeError(
      "CHM source must be Uint8Array, ArrayBuffer or Blob, not a filesystem path or URL"
    );
  }
  isOpen() {
    return this.archive.isOpen();
  }
  close() {
    this.archive.close();
  }
  listFiles(pattern) {
    return this.archive.listFiles(pattern);
  }
  listDirectories() {
    return this.archive.listDirectories();
  }
  exists(path) {
    return this.archive.exists(path);
  }
  getFileTree() {
    return this.archive.getFileTree();
  }
  glob(pattern) {
    return this.archive.glob(pattern);
  }
  readFile(path) {
    return Uint8Array.from(this.archive.readFile(path));
  }
  readText(path, encoding) {
    return this.archive.readText(path, encoding);
  }
  readHTML(path, encoding) {
    return this.archive.readHTML(path, encoding);
  }
  readJSON(path, encoding) {
    return this.archive.readJSON(path, encoding);
  }
  readImage(path) {
    return Uint8Array.from(this.archive.readImage(path));
  }
  readCSS(path, encoding) {
    return this.archive.readCSS(path, encoding);
  }
  readJS(path, encoding) {
    return this.archive.readJS(path, encoding);
  }
  readRange(path, start = 0, end) {
    return Uint8Array.from(this.archive.readRange(path, start, end));
  }
  createReadStream(path, start = 0, end) {
    const source = this.archive.createReadStream(path, start, end).getReader();
    return new ReadableStream(
      {
        async pull(controller) {
          try {
            const { done, value } = await source.read();
            if (done) {
              source.releaseLock();
              controller.close();
            } else {
              controller.enqueue(Uint8Array.from(value));
            }
          } catch (error) {
            source.releaseLock();
            controller.error(error);
          }
        },
        async cancel(reason) {
          try {
            await source.cancel(reason);
          } finally {
            source.releaseLock();
          }
        }
      },
      { highWaterMark: 0 }
    );
  }
  readMultiple(paths) {
    const result = /* @__PURE__ */ new Map();
    for (const [path, data] of this.archive.readMultiple(paths))
      result.set(path, Uint8Array.from(data));
    return result;
  }
  readWithMetadata(path) {
    const file = this.archive.readWithMetadata(path);
    return { ...file, data: Uint8Array.from(file.data) };
  }
  getFileInfo(path) {
    return this.archive.getFileInfo(path);
  }
  getFileSize(path) {
    return this.archive.getFileSize(path);
  }
  getCompressedSize(path) {
    return this.archive.getCompressedSize(path);
  }
  getCompressionRatio(path) {
    return this.archive.getCompressionRatio(path);
  }
  getMimeType(path) {
    return this.archive.getMimeType(path);
  }
  getMetadata() {
    return this.archive.getMetadata();
  }
  getTOC() {
    return this.archive.getTOC();
  }
  getIndex() {
    return this.archive.getIndex();
  }
  getDefaultPage() {
    return this.archive.getDefaultPage();
  }
  getHomePage() {
    return this.archive.getHomePage();
  }
  getNavigationLinks(path) {
    return this.archive.getNavigationLinks(path);
  }
  search(keyword, options) {
    return this.archive.search(keyword, options);
  }
  searchInFile(path, keyword, options) {
    return this.archive.searchInFile(path, keyword, options);
  }
  findFiles(pattern) {
    return this.archive.findFiles(pattern);
  }
  fuzzySearch(query, options) {
    return this.archive.fuzzySearch(query, options);
  }
  preload(paths) {
    this.archive.preload(paths);
  }
  getPreloadError() {
    return this.archive.getPreloadError();
  }
  clearCache() {
    this.archive.clearCache();
  }
  getCacheStats() {
    return this.archive.getCacheStats();
  }
  setCacheStrategy(strategy) {
    this.archive.setCacheStrategy(strategy);
  }
};
function packFiles2(files, options) {
  return Uint8Array.from(packFiles(files, options));
}
function packTemplate2(template, overrides, options) {
  return Uint8Array.from(packTemplate(template, overrides, options));
}
function updateArchive2(existing, changes, options) {
  return Uint8Array.from(
    updateArchive(
      existing instanceof ArrayBuffer ? new Uint8Array(existing) : existing,
      changes,
      options
    )
  );
}
var CHMKit = class _CHMKit {
  static from(input, options) {
    return new CHMReader(input, options);
  }
  static open(source, options) {
    return CHMReader.open(source, options);
  }
  static packFiles(files, options) {
    return packFiles2(files, options);
  }
  static packTemplate(template, overrides, options) {
    return packTemplate2(template, overrides, options);
  }
  static updateArchive(existing, changes, options) {
    return updateArchive2(existing, changes, options);
  }
  static readFile(source, path, options) {
    return _CHMKit.withReader(source, options, (reader) => reader.readFile(path));
  }
  static readText(source, path, encoding, options) {
    return _CHMKit.withReader(
      source,
      options,
      (reader) => reader.readText(path, encoding)
    );
  }
  static readHTML(source, path, encoding, options) {
    return _CHMKit.withReader(
      source,
      options,
      (reader) => reader.readHTML(path, encoding)
    );
  }
  static listFiles(source, pattern, options) {
    return _CHMKit.withReader(
      source,
      options,
      (reader) => reader.listFiles(pattern)
    );
  }
  static exists(source, path, options) {
    return _CHMKit.withReader(source, options, (reader) => reader.exists(path));
  }
  static getTOC(source, options) {
    return _CHMKit.withReader(source, options, (reader) => reader.getTOC());
  }
  static searchContent(source, keyword, options, readerOptions) {
    return _CHMKit.withReader(
      source,
      readerOptions,
      (reader) => reader.search(keyword, options)
    );
  }
  static async withReader(source, options, action) {
    const reader = await CHMReader.open(source, options);
    try {
      return await action(reader);
    } finally {
      reader.close();
    }
  }
};
var browser_default = CHMReader;

export {
  CacheStrategy,
  CHMReader,
  packFiles2 as packFiles,
  packTemplate2 as packTemplate,
  updateArchive2 as updateArchive,
  CHMKit,
  browser_default
};
//# sourceMappingURL=chunk-AEIDCH7W.mjs.map
