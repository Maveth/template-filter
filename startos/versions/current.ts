import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '#filter:0.1.0:2',
  releaseNotes: {
    en_US:
      'Accept Bitcoin Knots #knots:29.4.2:4 and newer. The previous requirement, >=29, does not match a Knots package.',
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
