import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '#filter:0.3.1:0',
  releaseNotes: {
    en_US:
      'A refill no longer adds a second spend of an input already in the template. The finished list is checked with the node, and a gateway receives it only after that check passes.',
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
