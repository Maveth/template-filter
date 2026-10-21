import { utils } from '@start9labs/start-sdk'
import { settingsJson } from '../fileModels/settings.json'
import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { listenPortDefault, nodePortDefault } from '../utils'

const { InputSpec, Value } = sdk

const toggle = (name: Parameters<typeof i18n>[0], def: boolean) =>
  Value.toggle({
    name: i18n(name),
    default: def,
    description: null,
  })

const inputSpec = InputSpec.of({
  nodeHost: Value.text({
    name: i18n('Node host'),
    required: false,
    default: '',
    placeholder: '',
    description: i18n('Blank uses the Bitcoin service on this server.'),
  }),
  nodePort: Value.number({
    name: i18n('Node port'),
    description: i18n(
      'Bitcoin RPC port. The StartOS package default is 8332, not a LAN port such as 65495.',
    ),
    required: true,
    default: nodePortDefault,
    min: 1,
    max: 65535,
    integer: true,
  }),
  listenHost: Value.text({
    name: i18n('Listen host'),
    required: true,
    default: '0.0.0.0',
    description: i18n(
      'Address this filter binds. 0.0.0.0 accepts the gateway on the bridge.',
    ),
  }),
  listenPort: Value.number({
    name: i18n('Listen port'),
    description: i18n('Port Datum Gateway must use as its Bitcoin RPC port.'),
    required: true,
    default: listenPortDefault,
    min: 1,
    max: 65535,
    integer: true,
  }),
  rejectfakeoutputs: toggle('Reject fake outputs', true),
  rejectdeadbranches: toggle('Reject dead branches', true),
  rejectbareenvelopes: toggle('Reject bare envelopes', true),
  rejectfakemultisig: toggle('Reject fake multisig', true),
  rejecttokenmessages: toggle('Reject token messages', true),
  rejectrunestones: toggle('Reject runestones', true),
  rejectcounterparty: toggle('Reject counterparty', true),
  rejectstamps: toggle('Reject stamps', true),
  rejectparasites: toggle('Reject parasites', true),
  permitbaremultisig: toggle('Permit bare multisig', false),
  permitbarepubkey: toggle('Permit bare pubkey', false),
  datacarrier: toggle('Allow OP_RETURN', false),
  datacarriersize: Value.number({
    name: i18n('OP_RETURN size'),
    description: i18n('Blank leaves the size to the other rules.'),
    required: false,
    default: 0,
    min: 0,
    integer: true,
  }),
  dust_sat_per_kvb: Value.number({
    name: i18n('Dust sat per kvB'),
    description: i18n('Blank leaves dust to the node.'),
    required: false,
    default: null,
    min: 0,
    integer: true,
  }),
  minfeerate_sat_vb: Value.number({
    name: i18n('Minimum fee sat per vB'),
    description: i18n('Blank leaves the fee to the node.'),
    required: false,
    default: null,
    min: 0,
    integer: false,
  }),
  blockmaxweight: Value.number({
    name: i18n('Max block weight'),
    description: i18n('Blank leaves the weight to the node.'),
    required: false,
    default: null,
    min: 1,
    integer: true,
  }),
})

export const filterConfig = sdk.Action.withInput(
  'filter-config',
  async () => ({
    name: i18n('Rules'),
    description: i18n('Which transactions to drop from the template'),
    warning: null,
    allowedStatuses: 'any',
    group: i18n('Rules'),
    visibility: 'enabled',
  }),
  inputSpec,
  async ({ effects }) => settingsJson.read().const(effects),
  ({ effects, input }) =>
    settingsJson.merge(effects, utils.nullToUndefined(input) as object),
)
