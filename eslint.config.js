import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

export default tseslint.config({ ignores: ["dist/"] }, ...tseslint.configs.recommended, prettier);
