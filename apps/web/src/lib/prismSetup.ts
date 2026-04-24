/**
 * Set up a single Prism instance for the entire app, with all languages
 * we emit snippets for registered on it. The returned `prism` value should
 * be passed to <Highlight prism={prism} …> so prism-react-renderer uses
 * this instance (with our extra grammars) rather than its vendored default
 * which only ships with markup/css/clike/js/jsx/ts/tsx.
 *
 * Importing `prismjs` has a side effect of setting `globalThis.Prism` to
 * the Prism instance, which the `prismjs/components/prism-*.js` files rely
 * on — they execute `(function(Prism){ Prism.languages.X = … })(Prism)` at
 * module top level and look up `Prism` in the global scope.
 *
 * Because ES module import statements are hoisted and run in source order,
 * we MUST do the `import prismjs` before any `import 'prismjs/components/…'`.
 * The simplest way to guarantee that is to put all of this in one module
 * that ends up before the consumer's other imports.
 */

// eslint-disable-next-line import/no-named-as-default
import Prism from "prismjs";

// Register every grammar we actually need. Order matters only where a
// language extends another (cpp → c, scala → java, tsx → typescript).
import "prismjs/components/prism-java";
import "prismjs/components/prism-python";
import "prismjs/components/prism-go";
import "prismjs/components/prism-ruby";
// prism-markup-templating MUST come before prism-php (php extends it and calls
// tokenizePlaceholders on it at load time). Other templating grammars that
// depend on it (smarty, twig, handlebars…) aren't registered here.
import "prismjs/components/prism-markup-templating";
import "prismjs/components/prism-php";
import "prismjs/components/prism-c";
import "prismjs/components/prism-cpp";
import "prismjs/components/prism-csharp";
import "prismjs/components/prism-yaml";
import "prismjs/components/prism-json";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-powershell";
import "prismjs/components/prism-docker";
import "prismjs/components/prism-hcl";
import "prismjs/components/prism-sql";
import "prismjs/components/prism-rust";
import "prismjs/components/prism-kotlin";
import "prismjs/components/prism-swift";
import "prismjs/components/prism-scala";
import "prismjs/components/prism-groovy";
import "prismjs/components/prism-r";
import "prismjs/components/prism-lua";
import "prismjs/components/prism-perl";
import "prismjs/components/prism-toml";
import "prismjs/components/prism-markdown";
import "prismjs/components/prism-protobuf";
import "prismjs/components/prism-dart";
import "prismjs/components/prism-elixir";
import "prismjs/components/prism-clojure";
import "prismjs/components/prism-objectivec";
import "prismjs/components/prism-properties";
import "prismjs/components/prism-ini";
import "prismjs/components/prism-makefile";
import "prismjs/components/prism-nginx";
import "prismjs/components/prism-scss";

export default Prism;
