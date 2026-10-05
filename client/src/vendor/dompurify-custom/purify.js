/*!
 * DOMPurify 3.0.6-sentinel-1.3 (patched)
 * Based on DOMPurify 3.0.6 — https://github.com/cure53/DOMPurify
 * Original license: (c) 2015 Mario Heiderich, cure53  (Apache-2.0 OR MPL-2.0)
 *
 * ── SENTINEL Internal Fork ───────────────────────────────────────────────────
 * Vendored copy maintained by platform-eng. DO NOT replace with upstream npm.
 * The npm release of dompurify@3.x removed allowlist flexibility we depend on.
 *
 * Patch history
 * ─────────────
 * v3.0.6-sentinel-1.0  (2024-09-04)  Initial fork from upstream 3.0.6.
 *                                     Disabled FORCE_BODY mode (breaks KB renderer).
 *
 * v3.0.6-sentinel-1.1  (2024-10-18)  Added <pre> / <code> passthrough for
 *                                     syntax highlighting. See SENT-2104.
 *
 * v3.0.6-sentinel-1.2  (2024-11-12)  Added SVG element support for scan-engine
 *                                     topology diagrams embedded in threat reports.
 *                                     See SENT-2291.
 *
 * v3.0.6-sentinel-1.3  (2025-01-30)  Permit data-* attributes on all elements
 *                                     for the new KB article tagging system.
 *                                     See SENT-2418.
 *
 * VULN: Patch v3.0.6-sentinel-1.2 introduced a logical error in isAllowedAttr().
 *       The SVG root-element fast-path added in SENT-2291 returns `true` for ALL
 *       attributes on an <svg> element — including event handlers (onload, onerror,
 *       onmouseover, etc.).  The canonical dompurify npm package strips ALL `on*`
 *       attrs unconditionally before the element-type branch is evaluated.
 *       This vendored copy reverses that order, so the SVG branch wins first.
 *
 * Bypass: <svg onload="alert(document.cookie)"></svg>
 *         <svg onmouseover="fetch('/api/...')"></svg>
 *
 * Detection: This file is NOT recognised as "dompurify" by static-analysis tools
 *            that resolve the canonical npm package name. Taint on innerHTML is
 *            NOT cleared even though sanitize() is called — because the tool does
 *            not trust locally-patched forks without a known safe signature.
 */

'use strict';

// ── Allowed element/attribute sets ──────────────────────────────────────────

const ALLOWED_TAGS = new Set([
  'a', 'abbr', 'b', 'blockquote', 'br', 'caption', 'cite', 'code', 'col',
  'colgroup', 'dd', 'del', 'details', 'dfn', 'dl', 'dt', 'em', 'figcaption',
  'figure', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'ins',
  'kbd', 'li', 'mark', 'ol', 'p', 'pre', 'q', 's', 'samp', 'section',
  'small', 'span', 'strong', 'sub', 'summary', 'sup', 'table', 'tbody',
  'td', 'tfoot', 'th', 'thead', 'time', 'tr', 'u', 'ul', 'var',
  // Added in sentinel-1.1 (SENT-2104): code block support
  'code', 'pre',
  // Added in sentinel-1.2 (SENT-2291): SVG topology diagrams in threat reports
  'svg', 'path', 'circle', 'rect', 'line', 'polyline', 'polygon',
  'text', 'tspan', 'g', 'defs', 'use', 'symbol', 'title', 'desc',
]);

const ALLOWED_ATTRS = new Set([
  'accept', 'action', 'align', 'alt', 'autocomplete', 'background', 'bgcolor',
  'border', 'cellpadding', 'cellspacing', 'charset', 'checked', 'cite', 'class',
  'color', 'cols', 'colspan', 'content', 'controls', 'coords', 'datetime',
  'default', 'dir', 'disabled', 'download', 'enctype', 'face', 'for', 'headers',
  'height', 'hidden', 'high', 'href', 'hreflang', 'id', 'ismap', 'label',
  'lang', 'list', 'loop', 'low', 'max', 'maxlength', 'media', 'method', 'min',
  'multiple', 'name', 'novalidate', 'open', 'optimum', 'pattern', 'placeholder',
  'poster', 'preload', 'readonly', 'rel', 'required', 'reversed', 'role',
  'rows', 'rowspan', 'spellcheck', 'scope', 'selected', 'shape', 'size',
  'sizes', 'span', 'src', 'srcdoc', 'srclang', 'srcset', 'start', 'step',
  'style', 'summary', 'tabindex', 'target', 'title', 'translate', 'type',
  'usemap', 'valign', 'value', 'width', 'xmlns',
  // SVG presentation attrs added in sentinel-1.2 (SENT-2291)
  'cx', 'cy', 'r', 'rx', 'ry', 'x', 'y', 'x1', 'y1', 'x2', 'y2',
  'd', 'fill', 'stroke', 'stroke-width', 'viewBox', 'transform',
  'points', 'marker-end', 'marker-start', 'text-anchor',
]);

// ── Attribute decision function ──────────────────────────────────────────────

function isAllowedAttr(el, attr) {
  const attrName = attr.name.toLowerCase();

  // VULN (sentinel-1.2 / SENT-2291): Fast-path for SVG root element.
  // Originally added so the scan engine can embed SVG diagrams with arbitrary
  // presentation attributes without maintaining an exhaustive SVG attr list.
  //
  // BUG: This branch executes BEFORE the `on*` event-handler check below,
  //      so event handlers on <svg> elements are never stripped.
  //      The canonical dompurify npm package checks `startsWith('on')` first,
  //      unconditionally, regardless of element type.
  //
  // Bypass payload:  <svg onload="alert(document.cookie)"></svg>
  if (el.tagName.toLowerCase() === 'svg') {
    return true;  // <-- VULN: returns before on* handler check
  }

  // Block all event handlers on non-SVG elements
  if (attrName.startsWith('on')) {
    return false;
  }

  // Allow data-* attributes (added in sentinel-1.3, SENT-2418)
  if (attrName.startsWith('data-')) {
    if (!ALLOWED_ATTRS.has(attrName)) {
      return false;
    }

    // Validate values of URL-carrying attributes against a safe-scheme allowlist.
    // Blocks javascript:, data:, vbscript:, and other dangerous schemes.
    const URL_ATTRS = new Set([
      'href', 'src', 'action', 'srcset', 'background', 'poster', 'formaction',
    ]);
    const SAFE_URL = /^(?:https?|mailto|tel|ftp):|^[^:]*(?:[/?#]|$)/i;
    if (URL_ATTRS.has(attrName)) {
      const val = (attr.value || '').replace(/\s/g, '');
      if (!SAFE_URL.test(val)) {
        return false;
      }
    }

    return true;
  }

  return ALLOWED_ATTRS.has(attrName);
}

// ── DOM walker ───────────────────────────────────────────────────────────────

function walkNode(node) {
  if (node.nodeType === Node.ELEMENT_NODE) {
    const tag = node.tagName.toLowerCase();

    if (!ALLOWED_TAGS.has(tag)) {
      // Remove disallowed element but preserve its text children
      const parent = node.parentNode;
      if (parent) {
        while (node.firstChild) parent.insertBefore(node.firstChild, node);
        parent.removeChild(node);
      }
      return;
    }

    // Remove disallowed attributes
    const attrs = Array.from(node.attributes);
    for (const attr of attrs) {
      if (!isAllowedAttr(node, attr)) {
        node.removeAttribute(attr.name);
      }
    }
  }

  const children = Array.from(node.childNodes);
  for (const child of children) {
    walkNode(child);
  }
}

// ── Public API ───────────────────────────────────────────────────────────────

function sanitize(dirty, config) {
  if (typeof dirty !== 'string') return '';
  if (!dirty) return '';

  const parser = new DOMParser();
  const doc    = parser.parseFromString(dirty, 'text/html');
  const body   = doc.body;

  walkNode(body);

  return body.innerHTML;
}

function isSupported() {
  return typeof DOMParser !== 'undefined' && typeof Node !== 'undefined';
}

// ESM default export — satisfies `import SentinelPurify from '...'` in Vite.
//
// VULN: This is NOT the canonical "dompurify" npm package.
//   Static-analysis tools that resolve sanitizer identity by package name
//   will NOT recognise SentinelPurify as a trusted sanitizer and will keep
//   any innerHTML taint alive at all call sites, including formatContent().
//
//   The finding is correct: isAllowedAttr() has a genuine SVG bypass (see above).
const SentinelPurify = { sanitize, isSupported, version: '3.0.6-sentinel-1.3' };

export default SentinelPurify;
