/**
 * ScAIm Text Normalizer
 * Strips invisible characters and normalizes Unicode homoglyphs before scanning.
 * Prevents evasion via zero-width chars, soft hyphens, Cyrillic/Greek lookalikes.
 */
const TextNormalizer = {
  /** Cyrillic/Greek homoglyphs → ASCII equivalents (most common in scam attacks). */
  HOMOGLYPHS: {
    "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0457": "i", "\u043A": "k", "\u0432": "B", "\u041D": "H",
    "\u041C": "M", "\u03B1": "a", "\u03BF": "o", "\u03C1": "p",
    "\u0131": "i"
  },

  /** Pre-compiled regex for all invisible/zero-width characters. */
  _INVISIBLE_RE: /[\u0000\u200B-\u200F\u061C\u180E\u2060-\u2064\uFEFF\u00AD\u17B4\u17B5]/g,

  /** Pre-compiled regex for all homoglyph characters. */
  _HOMOGLYPH_RE: /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0456\u0457\u043A\u0432\u041D\u041C\u03B1\u03BF\u03C1\u0131]/g,

  /**
   * Remove invisible chars and normalize homoglyphs.
   * Call on all text before pattern matching.
   * Uses two pre-compiled regexes instead of 32 split/join operations.
   */
  normalize(text) {
    if (!text) return "";
    const glyphs = this.HOMOGLYPHS;
    return text
      .replace(this._INVISIBLE_RE, "")
      .replace(this._HOMOGLYPH_RE, ch => glyphs[ch] || ch);
  }
};
