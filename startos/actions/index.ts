import { filterConfig } from './config'
import { sdk } from '../sdk'

export const actions = sdk.Actions.of().addAction(filterConfig)
