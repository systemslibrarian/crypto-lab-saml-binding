/**
 * One XML DOM, everywhere.
 *
 * This lab is about which element an application selected, so the one thing it
 * must not do is let the answer depend on which parser read the document. The
 * browser's native `DOMParser` and the DOM implementations available to a test
 * runner do not agree: `happy-dom`, for instance, parses namespaces correctly
 * and then returns nothing from `getElementsByTagNameNS`. A lesson whose
 * central claim is "the application read a different node" cannot be built on
 * a disagreement like that.
 *
 * So `@xmldom/xmldom` parses, serializes and owns every document here, in the
 * page and in the suite alike, and the globals `xmldsigjs` reaches for are
 * pointed at it. `Node` is only installed where the runtime has none; in a
 * browser the native one is already present with the same numeric constants.
 */
import { DOMParser, XMLSerializer, Node as XmlNode } from '@xmldom/xmldom';

type Mutable = Record<string, unknown>;
const globals = globalThis as unknown as Mutable;

globals.DOMParser = DOMParser;
globals.XMLSerializer = XMLSerializer;
if (typeof globals.Node === 'undefined') globals.Node = XmlNode;

/** A parsed XML document. `@xmldom/xmldom` types are structurally the DOM's. */
export type XmlDocument = ReturnType<DOMParser['parseFromString']>;
export type XmlElement = ReturnType<XmlDocument['createElement']>;

export const NS = {
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
} as const;

export function parseXml(xml: string): XmlDocument {
  return new DOMParser().parseFromString(xml, 'text/xml') as XmlDocument;
}

export function serializeXml(node: unknown): string {
  return new XMLSerializer().serializeToString(node as never);
}

/** Every element with the given namespace and local name, in document order. */
export function allElements(scope: unknown, ns: string, local: string): XmlElement[] {
  const list = (scope as XmlDocument).getElementsByTagNameNS(ns, local);
  const out: XmlElement[] = [];
  for (let i = 0; i < list.length; i += 1) out.push(list[i] as XmlElement);
  return out;
}

/**
 * Direct element children only.
 *
 * `getElementsByTagNameNS` is a DESCENDANT query, and a descendant query is
 * exactly the instrument a wrapping attack plays: it reaches through the
 * document into whatever the attacker nested. Every structural rule in this lab
 * that talks about position is written with this function instead.
 */
export function childElements(parent: unknown, ns: string, local: string): XmlElement[] {
  const out: XmlElement[] = [];
  const kids = (parent as XmlElement).childNodes;
  for (let i = 0; i < kids.length; i += 1) {
    const node = kids[i] as unknown as XmlElement;
    if (node.nodeType !== 1) continue;
    if (node.namespaceURI === ns && node.localName === local) out.push(node);
  }
  return out;
}

export function textOf(element: XmlElement | undefined | null): string {
  return element ? (element.textContent ?? '').trim() : '';
}

export function attr(element: XmlElement | undefined | null, name: string): string | null {
  if (!element) return null;
  return element.hasAttribute(name) ? element.getAttribute(name) : null;
}
