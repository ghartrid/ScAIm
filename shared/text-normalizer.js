/**
 * ScAIm Text Normalizer
 * Strips invisible characters and normalizes Unicode homoglyphs before scanning.
 * Prevents evasion via zero-width chars, soft hyphens, Cyrillic/Greek lookalikes.
 */
const TextNormalizer = {
  /** Zero-width and invisible Unicode characters used to break regex patterns. */
  INVISIBLE: "\u0000\u200B\u200C\u200D\u200E\u200F\u061C\u180E\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD\u17B4\u17B5",

  /** Cyrillic/Greek homoglyphs → ASCII equivalents (most common in scam attacks). */
  HOMOGLYPHS: {
    "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0457": "i", "\u043A": "k", "\u0432": "B", "\u041D": "H",
    "\u041C": "M", "\u03B1": "a", "\u03BF": "o", "\u03C1": "p",
    "\u0131": "i"
  },

  /**
   * Remove invisible chars and normalize homoglyphs.
   * Call on all text before pattern matching.
   */
  normalize(text) {
    if (!text) return "";
    let out = text;
    // Strip invisible characters
    for (let i = 0; i < this.INVISIBLE.length; i++) {
      out = out.split(this.INVISIBLE[i]).join("");
    }
    // Replace homoglyphs with ASCII equivalents
    for (const [glyph, ascii] of Object.entries(this.HOMOGLYPHS)) {
      out = out.split(glyph).join(ascii);
    }
    return out;
  }
};
