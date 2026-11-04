// The only way this app puts text on the page. Text is always a text node or `textContent`.
// Nothing in `src/` may use innerHTML, outerHTML, insertAdjacentHTML or document.write; a test
// reads the sources and fails if one appears.

export interface Props {
  class?: string;
  text?: string;
  attrs?: Record<string, string>;
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props.class) node.className = props.class;
  if (props.text !== undefined) node.textContent = props.text;
  for (const [name, value] of Object.entries(props.attrs ?? {})) node.setAttribute(name, value);
  for (const child of children) {
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

/** Remove everything inside `node`. */
export function clear(node: Element): void {
  node.replaceChildren();
}
