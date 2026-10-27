import { describe, expect, it } from 'vitest';
import { parseXml } from '../src/saml/dom.js';
import { canonicalize } from '../src/saml/verify.js';

/**
 * Exclusive canonicalization, checked against the specification rather than
 * against itself.
 *
 * Every other assertion in this suite about a digest or a signature is only as
 * good as the canonical bytes underneath it, and those bytes come from a
 * dependency. So the expected strings below are written out by hand from
 * Exclusive XML Canonicalization Version 1.0 (W3C Recommendation 18 July 2002)
 * and Canonical XML 1.0, not captured from a run:
 *
 *   - a namespace declaration is emitted only where it is VISIBLY UTILIZED,
 *     that is, used by the element's own name or by one of its attribute names
 *     (Excl-C14N 1.0 section 3), and only if an output ancestor has not already
 *     rendered the same prefix with the same value;
 *   - namespace declarations come first, sorted by prefix, then attributes
 *     sorted by namespace URI and then local name, with no-namespace attributes
 *     first;
 *   - empty elements are written as a start tag and an end tag, never
 *     self-closed;
 *   - in text, &, < and > are escaped; in attribute values, &, < and " are.
 *
 * If this file and the dependency ever disagree, the specification is the one
 * that is right and the dependency is the one that has to be replaced.
 */

function c14nOf(xml: string, pick?: (doc: ReturnType<typeof parseXml>) => unknown): string {
  const doc = parseXml(xml);
  return canonicalize(pick ? pick(doc) : doc.documentElement);
}

describe('exclusive canonicalization, against the specification', () => {
  it('drops a namespace declaration the element does not visibly utilize', () => {
    expect(c14nOf('<a:root xmlns:a="urn:a" xmlns:b="urn:b"><a:kid x="1"/></a:root>')).toBe(
      '<a:root xmlns:a="urn:a"><a:kid x="1"></a:kid></a:root>',
    );
  });

  it('drops an unused default namespace', () => {
    expect(c14nOf('<a:r xmlns="urn:d" xmlns:a="urn:a"><a:k/></a:r>')).toBe(
      '<a:r xmlns:a="urn:a"><a:k></a:k></a:r>',
    );
  });

  it('re-declares an inherited prefix when a subset is canonicalized alone', () => {
    // This is the property SAML Core 5.4.3 relies on: the canonical subset
    // carries its visibly utilized namespace instead of depending on an
    // unrendered ancestor declaration.
    expect(
      c14nOf('<a:root xmlns:a="urn:a" xmlns:b="urn:b"><a:kid x="1"/></a:root>', (doc) =>
        doc.getElementsByTagNameNS('urn:a', 'kid')[0],
      ),
    ).toBe('<a:kid xmlns:a="urn:a" x="1"></a:kid>');
  });

  it('orders namespaces before attributes, and attributes by namespace then local name', () => {
    expect(c14nOf('<r xmlns:p="urn:p" p:z="1" b="2" a="3"/>')).toBe(
      '<r xmlns:p="urn:p" a="3" b="2" p:z="1"></r>',
    );
  });

  it('escapes &, < and > in text', () => {
    expect(c14nOf('<t>a &lt; b &amp; c &gt; d</t>')).toBe('<t>a &lt; b &amp; c &gt; d</t>');
  });

  it('escapes & and < and the double quote in attribute values', () => {
    expect(c14nOf('<t v="a &lt; b &amp; c &quot; d"/>')).toBe(
      '<t v="a &lt; b &amp; c &quot; d"></t>',
    );
  });

  it('keeps > unescaped in an attribute value', () => {
    // Canonical XML escapes > in text but not in attribute values.
    expect(c14nOf('<t v="a &gt; b"/>')).toBe('<t v="a > b"></t>');
  });

  it('is byte-stable across a serialize and reparse round trip', () => {
    const expected = '<a:root xmlns:a="urn:a"><a:kid>text</a:kid></a:root>';
    const once = c14nOf('<a:root xmlns:a="urn:a"><a:kid>text</a:kid></a:root>');
    expect(once).toBe(expected);
    expect(c14nOf(once)).toBe(expected);
  });
});
