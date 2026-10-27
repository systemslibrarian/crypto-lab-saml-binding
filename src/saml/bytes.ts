/**
 * Byte helpers, kept in their own module with no DOM dependency.
 *
 * `keys.ts` needs hex to print a key fingerprint on page load, and dragging an
 * XML parser into the first bundle for that would be absurd.
 */
/** Hex, for digests and fingerprints shown to the learner. */
export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function base64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text.replace(/\s+/g, ''));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}
