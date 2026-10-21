import { i18n } from './i18n'
import { sdk } from './sdk'
import { listenPortDefault, rpcHostId, rpcInterfaceId } from './utils'

export const setInterfaces = sdk.setupInterfaces(async ({ effects }) => {
  const rpcMulti = sdk.MultiHost.of(effects, rpcHostId)
  const origin = await rpcMulti.bindPort(listenPortDefault, {
    protocol: 'http',
  })
  const rpc = sdk.createInterface(effects, {
    name: i18n('Filter RPC'),
    id: rpcInterfaceId,
    description: i18n('Where Datum Gateway sends getblocktemplate'),
    type: 'api',
    masked: false,
    schemeOverride: null,
    username: null,
    path: '',
    query: {},
  })
  const rpcReceipt = await origin.export([rpc])
  return [rpcReceipt]
})
