import { T } from '@start9labs/start-sdk'
import { sdk } from './sdk'

// Matches Bitcoin Knots on StartOS 0.4: startos/utils.ts rpcPort and rpcHostId.
// 65495 is a LAN port StartOS assigns per server, not this default.
export const nodePortDefault = 8332
export const btcRpcHostId = 'rpc'
export const listenPortDefault = 8336
export const dataDir = '/data'

export const rpcHostId = 'rpc'
export const rpcInterfaceId = 'rpc'

export const bitcoindRpcUrl = async (effects: T.Effects) => {
  const bridge = await sdk.host
    .getBridgeAddress(effects, {
      packageId: 'bitcoind',
      hostId: btcRpcHostId,
      internalPort: nodePortDefault,
      ssl: false,
    })
    .const()
  return bridge == null ? undefined : `http://${bridge}`
}
