import 'dotenv/config'
import parseArgs from 'minimist'

//-------------RECUPERACION ARGUMENTOS-----------
const optiones= { 
    alias:{p: 'port'},
    default:{p: 8080}
  }
export const arg = parseArgs(process.argv.slice(2), optiones)

//-------------RECUPERACION VARIABLES DE ENTORNO-----------
const PERSISTENCIA = process.env.PERSISTENCIA
const HOST_MONGO = process.env.HOST_MONGO
const PORT_MONGO = process.env.PORT_MONGO
const PORT = process.env.PORT||arg.port
const NODE_ENV = process.env.NODE_ENV

export {PERSISTENCIA, PORT_MONGO, HOST_MONGO, PORT, NODE_ENV}