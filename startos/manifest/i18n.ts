export const short = {
  en_US: 'Filter the block template between Datum and Bitcoin',
}

export const long = {
  en_US:
    'Sits between Datum Gateway and Bitcoin. Datum asks this service for a template. This service asks Bitcoin, drops transactions the rules name, and keeps the coinbase value and witness commitment consistent. Blake2b work is unchanged. StartOS 0.4 only.',
}

export const bitcoinDescription = {
  en_US: 'The node this filter reads templates from.',
}

export const datumDescription = {
  en_US: 'The gateway that must call this filter instead of Bitcoin directly.',
}
