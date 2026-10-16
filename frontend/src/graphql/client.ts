import { ApolloClient, InMemoryCache, HttpLink, split, from } from '@apollo/client'
import { setContext } from '@apollo/client/link/context'
import { onError } from '@apollo/client/link/error'
import { GraphQLWsLink } from '@apollo/client/link/subscriptions'
import { getMainDefinition } from '@apollo/client/utilities'
import { createClient } from 'graphql-ws'
import { getToken, logout, refresh } from '../auth'

const httpLink = new HttpLink({
  uri: '/api/v2/graphql',
})

// Attach the session's access token to every request.
const authLink = setContext((_, { headers }) => {
  const token = getToken()
  return {
    headers: {
      ...headers,
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
  }
})

// Expired/revoked session: try one refresh, otherwise go back to login.
const errorLink = onError(({ graphQLErrors }) => {
  const unauthenticated = graphQLErrors?.some((e) =>
    /authenticat|unauthori/i.test(e.message),
  )
  if (unauthenticated) {
    refresh().then((ok) => {
      if (!ok) {
        logout()
        window.location.assign('/login')
      }
    })
  }
})

// Same origin as the page (works behind haproxy's TLS front end too).
const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/api/v2/graphql/ws`

const wsLink = new GraphQLWsLink(
  createClient({
    url: wsUrl,
    connectionParams: () => {
      const token = getToken()
      return token ? { authorization: `Bearer ${token}` } : {}
    },
  })
)

const splitLink = split(
  ({ query }) => {
    const definition = getMainDefinition(query)
    return (
      definition.kind === 'OperationDefinition' &&
      definition.operation === 'subscription'
    )
  },
  wsLink,
  from([errorLink, authLink, httpLink]),
)

export const client = new ApolloClient({
  link: splitLink,
  cache: new InMemoryCache(),
})
