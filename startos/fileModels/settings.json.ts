import { FileHelper, z } from '@start9labs/start-sdk'
import { sdk } from '../sdk'
import { listenPortDefault, nodePortDefault } from '../utils'

const bool = z.boolean()

export const settingsShape = z.object({
  nodeHost: z.string().catch(''),
  nodePort: z.number().int().catch(nodePortDefault),
  listenHost: z.string().catch('0.0.0.0'),
  listenPort: z.number().int().catch(listenPortDefault),
  rejectfakeoutputs: bool.catch(true),
  rejectdeadbranches: bool.catch(true),
  rejectbareenvelopes: bool.catch(true),
  rejectfakemultisig: bool.catch(true),
  rejecttokenmessages: bool.catch(true),
  rejectrunestones: bool.catch(true),
  rejectcounterparty: bool.catch(true),
  rejectstamps: bool.catch(true),
  rejectparasites: bool.catch(true),
  permitbaremultisig: bool.catch(false),
  permitbarepubkey: bool.catch(false),
  datacarrier: bool.catch(false),
  datacarriersize: z.number().int().nullable().catch(0),
  dust_sat_per_kvb: z.number().int().nullable().catch(null),
  minfeerate_sat_vb: z.number().nullable().catch(null),
  blockmaxweight: z.number().int().nullable().catch(null),
})

export type Settings = z.infer<typeof settingsShape>

export const settingsJson = FileHelper.json(
  {
    base: sdk.volumes.main,
    subpath: 'settings.json',
  },
  settingsShape,
)

export const runtimeConfig = FileHelper.json(
  {
    base: sdk.volumes.main,
    subpath: 'config.json',
  },
  z.object({
    upstream: z.string(),
    profiles: z.array(z.object({
      name: z.string(),
      listen: z.string(),
      filters: z.record(z.string(), z.unknown()),
    })),
  }),
)
