import { setupManifest } from '@start9labs/start-sdk'
import {
  bitcoinDescription,
  datumDescription,
  long,
  short,
} from './i18n'

export const manifest = setupManifest({
  id: 'template-filter',
  title: 'Template Filter',
  license: 'mit',
  packageRepo: 'https://github.com/Maveth/template-filter',
  upstreamRepo: 'https://github.com/Maveth/template-filter',
  marketingUrl: 'https://github.com/Maveth/template-filter',
  donationUrl: null,
  description: { short, long },
  volumes: ['main'],
  images: {
    filter: {
      source: {
        dockerBuild: {
          dockerfile: 'Dockerfile',
          workdir: '.',
        },
      },
      arch: ['x86_64', 'aarch64'],
    },
  },
  dependencies: {
    bitcoind: {
      description: bitcoinDescription,
      optional: false,
      metadata: {
        title: 'Bitcoin',
        icon: 'https://raw.githubusercontent.com/Start9Labs/bitcoin-knots-startos/master/icon.svg',
      },
    },
    datum: {
      description: datumDescription,
      optional: false,
      metadata: {
        title: 'Datum Gateway',
        icon: 'https://raw.githubusercontent.com/Maveth/datum-gateway-startos/master/icon.svg',
      },
    },
  },
})
