import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '#filter:0.3.0:0',
  releaseNotes: {
    en_US:
      'Add the Knots policy checks a bare node would skip: data-carrier cost and full counting, bare data carriers, bare anchors, inscription tokens, bytes per sigop, legacy sigop count, and max script size. Block weight, size, and reserved limits can be set lower and are clamped to consensus.',
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
