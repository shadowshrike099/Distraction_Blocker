/**
 * @fileoverview Bloom Filter Implementation
 * @description A probabilistic data structure for efficient set membership testing
 * @version 1.0.0
 */

/**
 * Bloom Filter for efficient large dataset lookups
 * @class
 */
class BloomFilter {
  /**
   * Creates a new Bloom Filter
   * @param {number} [size=10000] - Size of the bit array
   * @param {number} [hashCount=7] - Number of hash functions to use
   */
  constructor(size = 10000, hashCount = 7) {
    /** @type {number} */
    this.size = size;

    /** @type {number} */
    this.hashCount = hashCount;

    /** @type {Uint8Array} */
    this.bitArray = new Uint8Array(Math.ceil(size / 8));

    /** @type {number} */
    this.itemCount = 0;
  }

  /**
   * Murmur-like hash function implementation
   * @private
   * @param {string} key - String to hash
   * @param {number} seed - Seed value for the hash
   * @returns {number} Hash value
   */
  _hash(key, seed) {
    let h1 = seed;
    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;

    for (let i = 0; i < key.length; i++) {
      let k1 = key.charCodeAt(i);

      k1 = Math.imul(k1, c1);
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = Math.imul(k1, c2);

      h1 ^= k1;
      h1 = (h1 << 13) | (h1 >>> 19);
      h1 = Math.imul(h1, 5) + 0xe6546b64;
    }

    h1 ^= key.length;
    h1 ^= h1 >>> 16;
    h1 = Math.imul(h1, 0x85ebca6b);
    h1 ^= h1 >>> 13;
    h1 = Math.imul(h1, 0xc2b2ae35);
    h1 ^= h1 >>> 16;

    return Math.abs(h1);
  }

  /**
   * Get multiple hash values for a key
   * @private
   * @param {string} item - Item to hash
   * @returns {number[]} Array of hash positions
   */
  _getHashPositions(item) {
    const positions = [];
    const hash1 = this._hash(item, 0);
    const hash2 = this._hash(item, hash1);

    for (let i = 0; i < this.hashCount; i++) {
      const position = Math.abs((hash1 + i * hash2) % this.size);
      positions.push(position);
    }

    return positions;
  }

  /**
   * Set a bit in the bit array
   * @private
   * @param {number} position - Bit position to set
   */
  _setBit(position) {
    const byteIndex = Math.floor(position / 8);
    const bitIndex = position % 8;
    this.bitArray[byteIndex] |= (1 << bitIndex);
  }

  /**
   * Get a bit from the bit array
   * @private
   * @param {number} position - Bit position to get
   * @returns {boolean} Whether the bit is set
   */
  _getBit(position) {
    const byteIndex = Math.floor(position / 8);
    const bitIndex = position % 8;
    return (this.bitArray[byteIndex] & (1 << bitIndex)) !== 0;
  }

  /**
   * Add an item to the Bloom filter
   * @param {string} item - Item to add
   * @returns {BloomFilter} Returns this for chaining
   */
  add(item) {
    if (typeof item !== 'string') {
      item = String(item);
    }

    const positions = this._getHashPositions(item);

    for (const position of positions) {
      this._setBit(position);
    }

    this.itemCount++;
    return this;
  }

  /**
   * Add multiple items to the Bloom filter
   * @param {string[]} items - Array of items to add
   * @returns {BloomFilter} Returns this for chaining
   */
  addAll(items) {
    for (const item of items) {
      this.add(item);
    }
    return this;
  }

  /**
   * Check if an item might be in the set
   * @param {string} item - Item to check
   * @returns {boolean} True if item might be in set, false if definitely not
   */
  contains(item) {
    if (typeof item !== 'string') {
      item = String(item);
    }

    const positions = this._getHashPositions(item);

    for (const position of positions) {
      if (!this._getBit(position)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Calculate the current false positive probability
   * @returns {number} Estimated false positive probability
   */
  getFalsePositiveRate() {
    const bitsSet = this._countBitsSet();
    const probability = Math.pow(bitsSet / this.size, this.hashCount);
    return probability;
  }

  /**
   * Count the number of bits set in the array
   * @private
   * @returns {number} Number of bits set
   */
  _countBitsSet() {
    let count = 0;
    for (let i = 0; i < this.bitArray.length; i++) {
      let byte = this.bitArray[i];
      while (byte) {
        count += byte & 1;
        byte >>= 1;
      }
    }
    return count;
  }

  /**
   * Get the number of items added
   * @returns {number} Number of items added
   */
  getItemCount() {
    return this.itemCount;
  }

  /**
   * Clear the Bloom filter
   * @returns {BloomFilter} Returns this for chaining
   */
  clear() {
    this.bitArray = new Uint8Array(Math.ceil(this.size / 8));
    this.itemCount = 0;
    return this;
  }

  /**
   * Create optimal Bloom filter for expected items
   * @static
   * @param {number} expectedItems - Expected number of items
   * @param {number} [falsePositiveRate=0.01] - Desired false positive rate
   * @returns {BloomFilter} Optimally sized Bloom filter
   */
  static createOptimal(expectedItems, falsePositiveRate = 0.01) {
    // Optimal size: m = -n*ln(p) / (ln(2)^2)
    const size = Math.ceil(-expectedItems * Math.log(falsePositiveRate) / Math.pow(Math.log(2), 2));

    // Optimal hash count: k = (m/n) * ln(2)
    const hashCount = Math.ceil((size / expectedItems) * Math.log(2));

    return new BloomFilter(size, Math.min(hashCount, 20));
  }

  /**
   * Serialize the Bloom filter to a JSON-compatible object
   * @returns {Object} Serialized Bloom filter
   */
  serialize() {
    return {
      size: this.size,
      hashCount: this.hashCount,
      itemCount: this.itemCount,
      bitArray: Array.from(this.bitArray)
    };
  }

  /**
   * Deserialize a Bloom filter from a JSON object
   * @static
   * @param {Object} data - Serialized Bloom filter data
   * @returns {BloomFilter} Restored Bloom filter
   */
  static deserialize(data) {
    const filter = new BloomFilter(data.size, data.hashCount);
    filter.itemCount = data.itemCount;
    filter.bitArray = new Uint8Array(data.bitArray);
    return filter;
  }
}

// Export for use in other modules
if (typeof self !== 'undefined') {
  self.BloomFilter = BloomFilter;
}
