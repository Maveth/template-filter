import { actions } from '../actions'
import { restoreInit } from '../backups'
import { setDependencies } from '../dependencies'
import { setInterfaces } from '../interfaces'
import { sdk } from '../sdk'
import { versionGraph } from '../versions'
import { settingsJson } from '../fileModels/settings.json'

const seedFiles = sdk.setupOnInit(async (effects) => {
  await settingsJson.merge(effects, {})
})

export const init = sdk.setupInit(
  restoreInit,
  versionGraph,
  setInterfaces,
  setDependencies,
  actions,
  seedFiles,
)

export const uninit = sdk.setupUninit(versionGraph)
