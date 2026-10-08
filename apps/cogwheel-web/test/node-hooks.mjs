// `npm test` runs the pure modules in src/lib under Node's own test runner,
// which strips their types itself. Vite resolves `@/` to src/ and imports
// that name no extension; this teaches Node the same two things, and nothing
// else, so the tests load the modules the app ships rather than copies.
import { registerHooks } from "node:module";

const SRC = new URL("../src/", import.meta.url);

registerHooks({
  resolve(specifier, context, nextResolve) {
    const target = specifier.startsWith("@/") ? new URL(specifier.slice(2), SRC).href : specifier;
    const local = target.startsWith("file:") || target.startsWith(".");
    return nextResolve(local && !/\.[cm]?[jt]sx?$/.test(target) ? `${target}.ts` : target, context);
  },
});
