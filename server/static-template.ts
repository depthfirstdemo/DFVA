const ALLOWED_TAGS = new Set([
  "article", "aside", "b", "blockquote", "br", "caption", "code", "dd", "div",
  "dl", "dt", "em", "figcaption", "figure", "footer", "h1", "h2", "h3", "h4",
  "h5", "h6", "header", "hr", "i", "li", "main", "mark", "nav", "ol", "p",
  "pre", "s", "section", "small", "span", "strong", "sub", "sup", "table",
  "tbody", "td", "tfoot", "th", "thead", "tr", "u", "ul",
]);

const VOID_TAGS = new Set(["br", "hr"]);

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export class StaticTemplateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StaticTemplateError";
  }
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, character => HTML_ESCAPES[character]);
}

/**
 * Render a deliberately small, non-executable subset of Pug.
 *
 * Only allowlisted tag names, indentation, and literal text are accepted. Pug
 * expressions, interpolation, attributes, includes, and mixins are rejected so
 * caller-controlled input is never compiled or evaluated as JavaScript.
 */
export function renderStaticTemplate(template: string): string {
  const output: string[] = [];
  const openTags: Array<{ tag: string; indentation: number }> = [];

  const closeTagsAtOrAbove = (indentation: number) => {
    while (openTags.length > 0 && indentation <= openTags[openTags.length - 1].indentation) {
      output.push(`</${openTags.pop()!.tag}>`);
    }
  };

  for (const [lineIndex, line] of template.replace(/\r\n?/g, "\n").split("\n").entries()) {
    if (line.trim() === "") continue;

    const indentationText = line.match(/^[ \t]*/)?.[0] ?? "";
    if (indentationText.includes("\t")) {
      throw new StaticTemplateError(`Tabs are not supported (line ${lineIndex + 1})`);
    }

    const indentation = indentationText.length;
    const content = line.slice(indentation);
    if (content.includes("#{") || content.includes("!{")) {
      throw new StaticTemplateError(`Interpolation is not supported (line ${lineIndex + 1})`);
    }

    closeTagsAtOrAbove(indentation);
    const parent = openTags[openTags.length - 1];
    if ((parent && indentation <= parent.indentation) || (!parent && indentation !== 0)) {
      throw new StaticTemplateError(`Invalid indentation (line ${lineIndex + 1})`);
    }

    if (content === "|" || content.startsWith("| ")) {
      output.push(escapeHtml(content === "|" ? "" : content.slice(2)));
      continue;
    }

    const tagMatch = /^([a-z][a-z0-9]*)(?:\s+(.*))?$/.exec(content);
    if (!tagMatch) {
      throw new StaticTemplateError(`Unsupported template syntax (line ${lineIndex + 1})`);
    }

    const [, tag, text = ""] = tagMatch;
    if (!ALLOWED_TAGS.has(tag)) {
      throw new StaticTemplateError(`Unsupported tag (line ${lineIndex + 1})`);
    }
    if (text.startsWith("=") || text.startsWith("!=")) {
      throw new StaticTemplateError(`Expressions are not supported (line ${lineIndex + 1})`);
    }
    if (VOID_TAGS.has(tag) && text !== "") {
      throw new StaticTemplateError(`Void tags cannot contain text (line ${lineIndex + 1})`);
    }

    output.push(`<${tag}>`);
    if (VOID_TAGS.has(tag)) continue;

    output.push(escapeHtml(text));
    openTags.push({ tag, indentation });
  }

  while (openTags.length > 0) {
    output.push(`</${openTags.pop()!.tag}>`);
  }

  return output.join("");
}
