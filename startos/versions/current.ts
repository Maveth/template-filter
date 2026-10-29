import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '#filter:0.3.3:0',
  releaseNotes: {
    en_US:
      'A saved template expires after two minutes. The next request refills from the node, and that list is sent only after the node accepts it. Gateways should stay pointed at the node until a later version is needed for new spam.',
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
