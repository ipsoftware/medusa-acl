// Unit tests only — they import nothing from @medusajs/* and run without a
// database or a Medusa container. The integration spec under
// `src/__tests__` needs a real Medusa project and is documented in the
// README as something to copy over, not something this repo's CI runs.
module.exports = {
  transform: {
    "^.+\\.[jt]s$": [
      "@swc/jest",
      {
        jsc: {
          parser: { syntax: "typescript", decorators: true },
          target: "es2022",
        },
      },
    ],
  },
  testEnvironment: "node",
  moduleFileExtensions: ["js", "ts", "json"],
  modulePathIgnorePatterns: ["dist/"],
  testMatch: ["**/src/**/__tests__/**/*.unit.spec.[jt]s"],
}
