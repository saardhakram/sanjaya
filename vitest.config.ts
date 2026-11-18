import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['src/server/**/*.ts', 'src/shared/**/*.ts'],
      exclude: ['src/server/index.ts', 'src/server/bootstrap.ts'],
      reporter: ['text', 'text-summary', 'lcov'],
      thresholds: {
        lines: 90,
        statements: 90,
        functions: 90,
        branches: 80,
      },
    },
  },
});
