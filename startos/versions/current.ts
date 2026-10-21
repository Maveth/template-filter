import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '#filter:0.1.0:1',
  releaseNotes: {
    en_US:
      'First StartOS 0.4 sideload. Depends on Bitcoin and Datum Gateway. Node address and listen address are configurable. Rule switches match the pool filter.',
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
