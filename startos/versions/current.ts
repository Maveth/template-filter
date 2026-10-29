import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '#filter:0.3.2:0',
  releaseNotes: {
    en_US:
      'A saved template keeps its transactions and takes the current clock from the node before it is sent to a gateway.',
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
