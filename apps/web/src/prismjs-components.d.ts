// Stub declarations for prismjs language component side-effect imports.
// @types/prismjs only declares the main "prismjs" module, not the per-language
// component files. Each import registers the language on the global Prism as
// a side effect, so an empty module declaration is enough to satisfy TS.
declare module "prismjs/components/*";

// Minimal stub for the prismjs main module — @types/prismjs isn't installed
// (we only use the runtime). The default export is the Prism object with
// `.languages` and the `.highlight(code, grammar, language)` helper.
declare module "prismjs" {
  const Prism: {
    languages: Record<string, unknown>;
    highlight: (code: string, grammar: unknown, language: string) => string;
    [key: string]: unknown;
  };
  export default Prism;
}
