import { ApolloClient, InMemoryCache, HttpLink, from, split } from '@apollo/client'
import { setContext } from '@apollo/client/link/context'
import { onError } from '@apollo/client/link/error'
import { GraphQLWsLink } from '@apollo/client/link/subscriptions'
import { getMainDefinition } from '@apollo/client/utilities'
import { createClient } from 'graphql-ws'
import { accessToken, logout, refreshSession } from '../api'

const httpLink = new HttpLink({ uri: '/api/v2/graphql' })

// Send the session's bearer token with every query/mutation.
const authLink = setContext((_, { headers }) => {
  const token = accessToken()
  return {
    headers: { ...headers, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  }
})

// An expired access token surfaces as an authentication error: refresh
// once, otherwise end the session (back to the login page).
const errorLink = onError(({ graphQLErrors, networkError }) => {
  const authFailure =
    graphQLErrors?.some((e) => /authenticat|unauthori|token/i.test(e.message)) ||
    (networkError !== undefined &&
      networkError !== null &&
      'statusCode' in networkError &&
      networkError.statusCode === 401)
  if (authFailure) {
    refreshSession().then((ok) => {
      if (!ok) logout()
    })
  }
})

// Subscriptions use the page's own origin, so they work behind haproxy and
// https (this used to be hardcoded to ws://localhost:8443).
const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/api/v2/graphql/ws`

const wsLink = new GraphQLWsLink(
  createClient({
    url: wsUrl,
    lazy: true,
    retryAttempts: Infinity,
    connectionParams: () => {
      const token = accessToken()
      return token ? { Authorization: `Bearer ${token}` } : {}
    },
  }),
)

const splitLink = split(
  ({ query }) => {
    const definition = getMainDefinition(query)
    return definition.kind === 'OperationDefinition' && definition.operation === 'subscription'
  },
  wsLink,
  from([errorLink, authLink, httpLink]),
)

export const client = new ApolloClient({
  link: splitLink,
  cache: new InMemoryCache(),
  defaultOptions: {
    watchQuery: { fetchPolicy: 'cache-and-network' },
  },
})
