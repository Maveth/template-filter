import { settingsJson, runtimeConfig, Settings } from './fileModels/settings.json'
import { i18n } from './i18n'
import { sdk } from './sdk'
import {
  bitcoindRpcUrl,
  dataDir,
  listenPortDefault,
  nodePortDefault,
} from './utils'

function upstreamFrom(settings: Settings, discovered: string | undefined): string {
  const host = (settings.nodeHost || '').trim()
  if (host) {
    const port = settings.nodePort || nodePortDefault
    return `http://${host}:${port}`
  }
  if (!discovered) {
    throw new Error('Bitcoin RPC address is not available yet')
  }
  return discovered
}

function filtersFrom(settings: Settings) {
  return {
    rejectfakeoutputs: settings.rejectfakeoutputs,
    rejectdeadbranches: settings.rejectdeadbranches,
    rejectbareenvelopes: settings.rejectbareenvelopes,
    rejectfakemultisig: settings.rejectfakemultisig,
    rejecttokenmessages: settings.rejecttokenmessages,
    rejectrunestones: settings.rejectrunestones,
    rejectcounterparty: settings.rejectcounterparty,
    rejectstamps: settings.rejectstamps,
    rejectparasites: settings.rejectparasites,
    permitbaremultisig: settings.permitbaremultisig,
    permitbarepubkey: settings.permitbarepubkey,
    datacarrier: settings.datacarrier,
    datacarriersize: settings.datacarriersize,
    dust_sat_per_kvb: settings.dust_sat_per_kvb,
    minfeerate_sat_vb: settings.minfeerate_sat_vb,
    blockmaxweight: settings.blockmaxweight,
  }
}

export const main = sdk.setupMain(async ({ effects }) => {
  const settings = (await settingsJson.read().const(effects)) ?? {
    nodeHost: '',
    nodePort: nodePortDefault,
    listenHost: '0.0.0.0',
    listenPort: listenPortDefault,
    rejectfakeoutputs: true,
    rejectdeadbranches: true,
    rejectbareenvelopes: true,
    rejectfakemultisig: true,
    rejecttokenmessages: true,
    rejectrunestones: true,
    rejectcounterparty: true,
    rejectstamps: true,
    rejectparasites: true,
    permitbaremultisig: false,
    permitbarepubkey: false,
    datacarrier: false,
    datacarriersize: 0,
    dust_sat_per_kvb: null,
    minfeerate_sat_vb: null,
    blockmaxweight: null,
  }
  const discovered = await bitcoindRpcUrl(effects)
  const listenPort = settings.listenPort || listenPortDefault
  await runtimeConfig.write(effects, {
    upstream: upstreamFrom(settings, discovered),
    profiles: [
      {
        name: 'default',
        listen: `${settings.listenHost || '0.0.0.0'}:${listenPort}`,
        filters: filtersFrom(settings),
      },
    ],
  })

  const sub = await sdk.SubContainer.eager(
    effects,
    { imageId: 'filter' },
    sdk.Mounts.of().mountVolume({
      volumeId: 'main',
      subpath: null,
      mountpoint: dataDir,
      readonly: false,
    }),
    'filter-sub',
  )

  return sdk.Daemons.of(effects).addDaemon('filter', {
    subcontainer: sub,
    exec: {
      command: ['python3', '/opt/template-filter/template_filter.py'],
    },
    requires: [],
    ready: {
      display: i18n('Filter RPC'),
      fn: () =>
        sdk.healthCheck.checkPortListening(effects, listenPort, {
          successMessage: i18n('Template filter is ready'),
          errorMessage: i18n('Template filter is not ready'),
        }),
    },
  })
})
