import { sdk } from './sdk'

export const setDependencies = sdk.setupDependencies(async () => {
  return {
    bitcoind: {
      kind: 'running',
      versionRange: '>=29',
      healthChecks: ['bitcoind'],
    },
    datum: {
      kind: 'running',
      versionRange: '*',
      healthChecks: [],
    },
  }
})
