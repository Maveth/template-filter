import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '#filter:0.2.0:0',
  releaseNotes: {
    en_US:
      'After a template is filtered, ask the node to fill the freed space and serve that fuller template on the same tip. The first answer is still the filtered template. A new block starts over. The added transactions stay inside the weight, byte, and sigop limits.',
  },
  migrations: {
    up: async () => {},
    down: async () => {},
    other: {
      ['*']: {
        up: async () => {},
        down: async () => {},
      },
    },
  },
})
