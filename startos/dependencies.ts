import { sdk } from './sdk'

export const setDependencies = sdk.setupDependencies(async () => {
  return {
    bitcoind: {
      kind: 'running',
      versionRange: '>=#knots:29.4.2:4',
      healthChecks: ['bitcoind'],
    },
    datum: {
      kind: 'running',
      versionRange: '*',
      healthChecks: [],
    },
  }
})
