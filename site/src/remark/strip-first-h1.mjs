// The Manual layout renders the page title (from the manifest) as the <h1>.
// Drop the doc's own leading top-level heading so we don't show two titles.
export default function stripFirstH1() {
  return (tree) => {
    const idx = tree.children.findIndex((n) => n.type === 'heading' && n.depth === 1);
    if (idx !== -1) tree.children.splice(idx, 1);
  };
}
