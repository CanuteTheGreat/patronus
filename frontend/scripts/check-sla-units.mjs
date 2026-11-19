// The GraphQL SLA fields are already percentages; scaling them by 100 showed
// "9995.00%". Fail if the page multiplies them again.
import { readFileSync } from 'node:fs'
const src = readFileSync(new URL('../src/components/SLA.tsx', import.meta.url), 'utf8')
const bad = src.match(/(Availability|PacketLoss)\s*\*\s*100/g)
if (bad) {
  console.error('SLA.tsx rescales percent fields by 100:', bad.join(', '))
  process.exit(1)
}
console.log('SLA units ok')
